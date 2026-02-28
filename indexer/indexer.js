require('dotenv').config();

const path = require('path');
const { createPublicClient, getAddress, http, parseAbi, parseAbiItem } = require('viem');
const { readCache, writeCache } = require('./cacheStore');

const RECEIPT_MINTED_EVENT = parseAbiItem(
  'event ReceiptMinted(uint256 indexed tokenId,address indexed granter,address indexed grantee,bytes32[] scopeHashes,uint64 expiresAt,bytes32 proofHash)'
);
const RECEIPT_REVOKED_EVENT = parseAbiItem(
  'event ReceiptRevoked(uint256 indexed tokenId,uint64 indexed revokedAt)'
);

const abi = parseAbi([
  'function receipts(uint256 tokenId) view returns (address granter,address grantee,bytes32 proofHash,uint64 issuedAt,uint64 expiresAt,uint64 revokedAt,bool active,bool exists)',
  'function getScopeHashes(uint256 tokenId) view returns (bytes32[])',
]);

function toBlockNumber(value, fallback = 0) {
  if (value == null) return fallback;
  if (typeof value === 'bigint') return Number(value);
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function createReport(cache) {
  return {
    cachedReceiptsCount: Object.keys(cache.receipts || {}).length,
    lastProcessedBlock: Number(cache.meta?.lastIndexedBlock || 0),
  };
}

async function main() {
  const {
    RPC_URL,
    CONTRACT_ADDRESS,
    CHAIN_ID,
    INDEXER_CACHE_PATH = path.join('indexer', 'receipt-cache.json'),
    INDEXER_START_BLOCK = '0',
    INDEXER_POLL_INTERVAL_MS = '4000',
  } = process.env;

  const mode = (process.argv[2] || 'sync').toLowerCase();
  if (!['sync', 'watch'].includes(mode)) {
    throw new Error('Usage: node indexer/indexer.js [sync|watch]');
  }

  if (!RPC_URL || !CONTRACT_ADDRESS) {
    throw new Error('Missing env: RPC_URL and CONTRACT_ADDRESS are required');
  }

  const address = getAddress(CONTRACT_ADDRESS);
  const client = createPublicClient({ transport: http(RPC_URL) });
  let cache = readCache(INDEXER_CACHE_PATH);

  cache.meta.chainId = CHAIN_ID ? Number(CHAIN_ID) : cache.meta.chainId;
  cache.meta.contractAddress = address;

  async function upsertReceipt(tokenId) {
    const id = String(tokenId);
    const receipt = await client.readContract({
      address,
      abi,
      functionName: 'receipts',
      args: [BigInt(tokenId)],
    });

    const scopeHashes = await client.readContract({
      address,
      abi,
      functionName: 'getScopeHashes',
      args: [BigInt(tokenId)],
    });

    cache.receipts[id] = {
      tokenId: Number(tokenId),
      granter: getAddress(receipt[0]),
      grantee: getAddress(receipt[1]),
      proofHash: String(receipt[2]),
      issuedAt: Number(receipt[3]),
      expiresAt: Number(receipt[4]),
      revokedAt: Number(receipt[5]),
      active: Boolean(receipt[6]),
      exists: Boolean(receipt[7]),
      scopeHashes: scopeHashes.map(String),
      updatedAt: Date.now(),
    };
  }

  async function markRevoked(tokenId, revokedAt) {
    const id = String(tokenId);
    if (!cache.receipts[id]) {
      await upsertReceipt(tokenId);
      return;
    }
    cache.receipts[id] = {
      ...cache.receipts[id],
      active: false,
      revokedAt: Number(revokedAt),
      updatedAt: Date.now(),
    };
  }

  async function getEventBatch(fromBlock, toBlock) {
    const [mintedLogs, revokedLogs] = await Promise.all([
      client.getLogs({ address, event: RECEIPT_MINTED_EVENT, fromBlock, toBlock }),
      client.getLogs({ address, event: RECEIPT_REVOKED_EVENT, fromBlock, toBlock }),
    ]);

    return [...mintedLogs, ...revokedLogs].sort((a, b) => {
      const blockDelta = Number((a.blockNumber || 0n) - (b.blockNumber || 0n));
      if (blockDelta !== 0) return blockDelta;
      return Number((a.logIndex || 0) - (b.logIndex || 0));
    });
  }

  async function processRange(fromBlock, toBlock) {
    if (toBlock < fromBlock) return;
    const logs = await getEventBatch(fromBlock, toBlock);

    for (const log of logs) {
      if (log.eventName === 'ReceiptMinted') {
        await upsertReceipt(log.args.tokenId);
      }
      if (log.eventName === 'ReceiptRevoked') {
        await markRevoked(log.args.tokenId, log.args.revokedAt);
      }
      cache.meta.lastIndexedBlock = Math.max(
        Number(cache.meta.lastIndexedBlock || 0),
        toBlockNumber(log.blockNumber, 0)
      );
    }

    cache.meta.lastIndexedBlock = Math.max(Number(cache.meta.lastIndexedBlock || 0), toBlockNumber(toBlock, 0));
    cache = writeCache(INDEXER_CACHE_PATH, cache);
  }

  async function syncOnce() {
    const startFrom = Math.max(Number(cache.meta.lastIndexedBlock || 0), Number(INDEXER_START_BLOCK || 0));
    const fromBlock = BigInt(startFrom);
    const toBlock = await client.getBlockNumber();
    await processRange(fromBlock, toBlock);
    console.log(JSON.stringify(createReport(cache), null, 2));
  }

  async function watchLoop() {
    await syncOnce();

    const pollIntervalMs = Math.max(1000, Number(INDEXER_POLL_INTERVAL_MS || 4000));
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const latestBlock = await client.getBlockNumber();
      const from = BigInt(Number(cache.meta.lastIndexedBlock || 0) + 1);
      if (latestBlock >= from) {
        await processRange(from, latestBlock);
        console.log(JSON.stringify(createReport(cache), null, 2));
      }
      await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
    }
  }

  if (mode === 'sync') {
    await syncOnce();
    return;
  }

  await watchLoop();
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
