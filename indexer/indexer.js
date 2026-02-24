require('dotenv').config();

const path = require('path');
const { createPublicClient, getAddress, http, parseAbi } = require('viem');
const { readCache, writeCache } = require('./cacheStore');

const abi = parseAbi([
  'event ReceiptMinted(uint256 indexed tokenId,address indexed granter,address indexed grantee,bytes32[] scopeHashes,uint64 expiresAt,bytes32 proofHash)',
  'event ReceiptRevoked(uint256 indexed tokenId,uint64 indexed revokedAt)',
  'function receipts(uint256 tokenId) view returns (address granter,address grantee,bytes32 proofHash,uint64 issuedAt,uint64 expiresAt,uint64 revokedAt,bool active,bool exists)',
  'function getScopeHashes(uint256 tokenId) view returns (bytes32[])',
]);

async function main() {
  const {
    RPC_URL,
    CONTRACT_ADDRESS,
    CHAIN_ID,
    INDEXER_CACHE_PATH = path.join('indexer', 'receipt-cache.json'),
    INDEXER_START_BLOCK = '0',
  } = process.env;

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

  async function backfill() {
    const fromBlock = BigInt(
      Math.max(Number(cache.meta.lastIndexedBlock || 0), Number(INDEXER_START_BLOCK || 0))
    );
    const toBlock = await client.getBlockNumber();

    const mintedLogs = await client.getLogs({
      address,
      event: abi.find((e) => e.type === 'event' && e.name === 'ReceiptMinted'),
      fromBlock,
      toBlock,
    });
    for (const log of mintedLogs) {
      await upsertReceipt(Number(log.args.tokenId));
    }

    const revokedLogs = await client.getLogs({
      address,
      event: abi.find((e) => e.type === 'event' && e.name === 'ReceiptRevoked'),
      fromBlock,
      toBlock,
    });
    for (const log of revokedLogs) {
      await markRevoked(Number(log.args.tokenId), Number(log.args.revokedAt));
    }

    cache.meta.lastIndexedBlock = Number(toBlock);
    cache = writeCache(INDEXER_CACHE_PATH, cache);
  }

  await backfill();
  console.log(`Indexer cache hydrated at ${INDEXER_CACHE_PATH}`);

  client.watchContractEvent({
    address,
    abi,
    eventName: 'ReceiptMinted',
    onLogs: async (logs) => {
      for (const log of logs) {
        await upsertReceipt(Number(log.args.tokenId));
        cache.meta.lastIndexedBlock = Math.max(cache.meta.lastIndexedBlock || 0, Number(log.blockNumber || 0n));
      }
      cache = writeCache(INDEXER_CACHE_PATH, cache);
    },
    onError: (error) => {
      console.error('Minted watcher error', error);
    },
  });

  client.watchContractEvent({
    address,
    abi,
    eventName: 'ReceiptRevoked',
    onLogs: async (logs) => {
      for (const log of logs) {
        await markRevoked(Number(log.args.tokenId), Number(log.args.revokedAt));
        cache.meta.lastIndexedBlock = Math.max(cache.meta.lastIndexedBlock || 0, Number(log.blockNumber || 0n));
      }
      cache = writeCache(INDEXER_CACHE_PATH, cache);
    },
    onError: (error) => {
      console.error('Revoked watcher error', error);
    },
  });

  process.stdin.resume();
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
