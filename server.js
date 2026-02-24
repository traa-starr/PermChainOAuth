require('dotenv').config();

const express = require('express');
const jwt = require('jsonwebtoken');
const path = require('path');
const { SiweMessage, generateNonce } = require('siwe');
const { createPublicClient, http, parseAbi, getAddress, keccak256, toBytes, isAddress } = require('viem');
const { readCache, writeCache } = require('./indexer/cacheStore');

const DEFAULT_CHAIN_ID = 11155111;

function hashScope(scope) {
  return keccak256(toBytes(String(scope)));
}

function createNonceStore() {
  const nonces = new Map();
  const ttlMs = 10 * 60 * 1000;

  return {
    issue({ address, purpose = 'authorize' }) {
      const nonce = generateNonce();
      nonces.set(nonce, {
        address: address ? getAddress(address) : null,
        purpose,
        expiresAt: Date.now() + ttlMs,
      });
      return nonce;
    },
    consume({ nonce, address, purpose }) {
      const entry = nonces.get(nonce);
      if (!entry) throw new Error('Invalid nonce');
      if (Date.now() > entry.expiresAt) {
        nonces.delete(nonce);
        throw new Error('Expired nonce');
      }
      if (entry.purpose !== purpose) throw new Error('Nonce purpose mismatch');
      if (entry.address && getAddress(address) !== entry.address) {
        throw new Error('Nonce address mismatch');
      }
      nonces.delete(nonce);
      return true;
    },
  };
}

function createViemReceiptClient({ rpcUrl, contractAddress }) {
  const client = createPublicClient({ transport: http(rpcUrl) });
  const address = getAddress(contractAddress);
  const abi = parseAbi([
    'function receipts(uint256 tokenId) view returns (address granter,address grantee,bytes32 proofHash,uint64 issuedAt,uint64 expiresAt,uint64 revokedAt,bool active,bool exists)',
    'function getScopeHashes(uint256 tokenId) view returns (bytes32[])',
    'function isValid(uint256 tokenId,bytes32 scopeHash,uint256 timestamp) view returns (bool)',
    'function hasScopeHash(uint256 tokenId,bytes32 scopeHash) view returns (bool)',
  ]);

  async function readReceipt(receiptId) {
    const [raw, scopeHashes] = await Promise.all([
      client.readContract({
        address,
        abi,
        functionName: 'receipts',
        args: [BigInt(receiptId)],
      }),
      client.readContract({
        address,
        abi,
        functionName: 'getScopeHashes',
        args: [BigInt(receiptId)],
      }),
    ]);



    const scopeHashes = await client.readContract({
      address,
      abi,
      functionName: 'getScopeHashes',
      args: [BigInt(receiptId)],
    });


    return {
      receiptId: Number(receiptId),
      granter: getAddress(raw[0]),
      grantee: getAddress(raw[1]),

      proofHash: raw[2],

      scopeHashes: scopeHashes.map(String),
      proofHash: String(raw[2]),

      issuedAt: Number(raw[3]),
      expiresAt: Number(raw[4]),
      revokedAt: Number(raw[5]),
      active: Boolean(raw[6]),
      exists: Boolean(raw[7]),

      scopeHashes,

      updatedAt: Date.now(),

    };
  }

  async function hasScopeHash({ receiptId, requiredScopeHash }) {
    return client.readContract({
      address,
      abi,
      functionName: 'hasScopeHash',
      args: [BigInt(receiptId), requiredScopeHash],
    });
  }

  async function isValid({ receiptId, requiredScopeHash, now }) {
    return client.readContract({
      address,
      abi,
      functionName: 'isValid',
      args: [BigInt(receiptId), requiredScopeHash, BigInt(now)],
    });
  }

  return { readReceipt, hasScopeHash, isValid };
}

function createCachedReceiptClient({ receiptClient, cachePath = path.join('indexer', 'receipt-cache.json'), staleMs = 30_000 }) {
  function getCachedEntry(receiptId) {
    const cache = readCache(cachePath);
    return { cache, entry: cache.receipts[String(receiptId)] };
  }

  async function refreshReceipt(receiptId) {
    const fresh = await receiptClient.readReceipt(receiptId);
    const cache = readCache(cachePath);
    cache.receipts[String(receiptId)] = {
      tokenId: Number(receiptId),
      ...fresh,
      updatedAt: Date.now(),
    };
    writeCache(cachePath, cache);
    return fresh;
  }

  async function readReceipt(receiptId) {
    const { entry } = getCachedEntry(receiptId);
    if (entry && Date.now() - Number(entry.updatedAt || 0) <= staleMs) {
      return entry;
    }
    return refreshReceipt(receiptId);
  }

  async function isValid({ receiptId, requiredScopeHash, now }) {
    const { entry } = getCachedEntry(receiptId);
    if (entry) {
      const notRevoked = Boolean(entry.active) && Number(entry.revokedAt || 0) === 0;
      const notExpired = Number(entry.expiresAt || 0) === 0 || now <= Number(entry.expiresAt);
      const hasRequiredScope = !requiredScopeHash || entry.scopeHashes.includes(requiredScopeHash);

      if (Date.now() - Number(entry.updatedAt || 0) <= staleMs) {
        return notRevoked && notExpired && hasRequiredScope;
      }
    }

    const refreshed = await refreshReceipt(receiptId);
    const notRevoked = Boolean(refreshed.active) && Number(refreshed.revokedAt || 0) === 0;
    const notExpired = Number(refreshed.expiresAt || 0) === 0 || now <= Number(refreshed.expiresAt);
    const hasRequiredScope = !requiredScopeHash || refreshed.scopeHashes.includes(requiredScopeHash);
    return notRevoked && notExpired && hasRequiredScope;
  }

  return {
    readReceipt,
    isValid,
    refreshReceipt,
  };
}

async function verifySiwe({ message, signature, expectedDomain, expectedChainId }) {
  const siwe = new SiweMessage(message);
  const result = await siwe.verify({ signature, domain: expectedDomain });
  if (!result.success) throw new Error('SIWE verification failed');
  if (expectedChainId && Number(siwe.chainId) !== Number(expectedChainId)) {
    throw new Error(`Unexpected chainId ${siwe.chainId}`);
  }
  return { siwe, address: getAddress(siwe.address) };
}

function createBridgeApp({
  chainId = DEFAULT_CHAIN_ID,
  contractAddress,
  jwtSecret,
  siweDomain = 'localhost',
  tokenTtlSeconds = 900,
  receiptTtlSeconds = 3600,
  requiredScope = 'ai:train_data',
  receiptClient,
  nonceStore = createNonceStore(),
}) {
  if (!jwtSecret) throw new Error('jwtSecret is required');
  if (!contractAddress) throw new Error('contractAddress is required');
  if (!receiptClient) throw new Error('receiptClient is required');

  const app = express();
  app.use(express.json());

  app.post('/nonce', (req, res) => {
    const { address, purpose = 'authorize' } = req.body || {};
    if (address && !isAddress(address)) {
      return res.status(400).json({ error: 'Invalid address' });
    }
    const nonce = nonceStore.issue({ address, purpose });
    return res.json({ nonce, purpose, domain: siweDomain, chainId: Number(chainId) });
  });

  app.post('/authorize', async (req, res) => {
    try {
      const {
        siweMessage,
        siweSignature,
        grantee,
        scopes = [],
        metadataURI = '',
        expiresAt,
        mode = 'client-mint',
        mintWithSig = null,
      } = req.body || {};
      if (!siweMessage || !siweSignature || !grantee) {
        return res.status(400).json({ error: 'siweMessage, siweSignature, grantee are required' });
      }
      if (!isAddress(grantee)) {
        return res.status(400).json({ error: 'Invalid grantee address' });
      }

      const normalizedScopes = scopes.map((s) => String(s).trim()).filter(Boolean);
      if (normalizedScopes.length === 0) {
        return res.status(400).json({ error: 'At least one scope is required' });
      }

      const { siwe, address: granter } = await verifySiwe({
        message: siweMessage,
        signature: siweSignature,
        expectedDomain: siweDomain,
        expectedChainId: chainId,
      });
      nonceStore.consume({ nonce: siwe.nonce, address: granter, purpose: 'authorize' });

      const scopeHashes = normalizedScopes.map(hashScope);
      const now = Math.floor(Date.now() / 1000);
      const resolvedExpiresAt = Number(expiresAt || now + Number(receiptTtlSeconds));
      const proofHash = keccak256(toBytes(JSON.stringify(scopeHashes)));

      const mintIntent = {
        mode,
        contractAddress: getAddress(contractAddress),
        chainId: Number(chainId),
        granter,
        grantee: getAddress(grantee),
        scopeHashes,
        expiresAt: resolvedExpiresAt,
        proofHash,
        metadataURI,
      };

      if (mode === 'gasless') {
        if (!mintWithSig) {
          return res.status(400).json({ error: 'mintWithSig payload is required for gasless mode' });
        }
        if (typeof receiptClient.relayMintWithSig !== 'function') {
          return res.status(501).json({ error: 'Gasless mode unavailable: relayMintWithSig not configured' });
        }
        const relayResult = await receiptClient.relayMintWithSig({
          granter,
          grantee: getAddress(grantee),
          scopeHashes,
          expiresAt: resolvedExpiresAt,
          metadataURI,
          proofHash,
          mintWithSig,
        });
        return res.json({ mintIntent, relayResult });
      }

      return res.json({
        mintIntent: {
          ...mintIntent,
          mintFunction: 'mint(address granter, address grantee, bytes32[] scopeHashes, string metadataURI, bytes32 proofHash, uint64 expiresAt)',
          note: 'User wallet must submit mint transaction. granter must equal msg.sender on-chain.',
        },
      });
    } catch (error) {
      return res.status(400).json({ error: error.message });
    }
  });

  app.post('/token', async (req, res) => {
    try {
      const {
        receiptId,
        siweMessage,
        siweSignature,
        requiredScopeHashes = [hashScope(requiredScope)],
        aud = getAddress(contractAddress),
      } = req.body || {};
      if (!receiptId || !siweMessage || !siweSignature) {
        return res.status(400).json({ error: 'receiptId, siweMessage, siweSignature are required' });
      }

      const { siwe, address: siweAddress } = await verifySiwe({
        message: siweMessage,
        signature: siweSignature,
        expectedDomain: siweDomain,
        expectedChainId: chainId,
      });
      nonceStore.consume({ nonce: siwe.nonce, address: siweAddress, purpose: 'token' });

      const receipt = await receiptClient.readReceipt(receiptId);
      if (siweAddress !== receipt.granter) {
        return res.status(403).json({ error: 'SIWE signer must match receipt granter' });
      }

      const now = Math.floor(Date.now() / 1000);
      let validForAnyRequestedScope = false;
      for (const requiredScopeHash of requiredScopeHashes) {
        // eslint-disable-next-line no-await-in-loop
        const hasScope = typeof receiptClient.hasScopeHash === 'function'
          ? await receiptClient.hasScopeHash({ receiptId, requiredScopeHash })
          : receipt.scopeHashes.includes(requiredScopeHash);
        if (!hasScope) continue;
        // eslint-disable-next-line no-await-in-loop
        const ok = await receiptClient.isValid({ receiptId, requiredScopeHash, now });
        if (ok) {
          validForAnyRequestedScope = true;
          break;
        }
      }
      if (!validForAnyRequestedScope) {
        return res.status(403).json({ error: 'Receipt invalid for required scope hash(es)' });
      }

      const jwtExp = Math.min(now + Number(tokenTtlSeconds), receipt.expiresAt || now + Number(tokenTtlSeconds));
      const payload = {
        sub: receipt.grantee,
        receiptId: Number(receiptId),
        granter: receipt.granter,
        grantee: receipt.grantee,
        scopeHashes: receipt.scopeHashes,
        iat: now,
        exp: jwtExp,
        aud,
        iss: `permchain-oauth:${Number(chainId)}`,
        chainId: Number(chainId),
      };
      const accessToken = jwt.sign(payload, jwtSecret, { algorithm: 'HS256' });

      return res.json({ token_type: 'Bearer', expires_in: Math.max(0, jwtExp - now), access_token: accessToken });
    } catch (error) {
      return res.status(400).json({ error: error.message });
    }
  });

  async function introspectToken(token, requiredScopeHash = hashScope(requiredScope)) {
    try {
      const decoded = jwt.verify(token, jwtSecret);
      if (!decoded.scopeHashes || !decoded.scopeHashes.includes(requiredScopeHash)) {
        return { active: false };
      }

      const now = Math.floor(Date.now() / 1000);
      const valid = await receiptClient.isValid({
        receiptId: decoded.receiptId,
        requiredScopeHash,
        now,
      });
      if (!valid) return { active: false };

      return {
        active: true,
        sub: decoded.sub,
        scopeHashes: decoded.scopeHashes,
        exp: decoded.exp,
        receiptId: decoded.receiptId,
        granter: decoded.granter,
        grantee: decoded.grantee,
        aud: decoded.aud,
        iss: decoded.iss,
      };
    } catch {
      return { active: false };
    }
  }

  app.post('/introspect', async (req, res) => {
    const { token, requiredScopeHash } = req.body || {};
    if (!token) return res.status(400).json({ active: false, error: 'token is required' });
    const result = await introspectToken(token, requiredScopeHash || hashScope(requiredScope));
    return res.json(result);
  });

  app.get('/data', async (req, res) => {
    const authz = req.headers.authorization || '';
    const token = authz.startsWith('Bearer ') ? authz.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Missing bearer token' });

    const result = await introspectToken(token, hashScope(requiredScope));
    if (!result.active) return res.status(403).json({ error: 'Token inactive for required scope' });

    return res.json({
      data: 'Protected AI dataset endpoint',
      receiptId: result.receiptId,
      subject: result.sub,
      requiredScopeHash: hashScope(requiredScope),
    });
  });

  return app;
}

if (require.main === module) {
  const {
    PORT = '3001',
    RPC_URL,
    CHAIN_ID = String(DEFAULT_CHAIN_ID),
    CONTRACT_ADDRESS,
    JWT_SECRET,
    SIWE_DOMAIN = 'localhost',
    TOKEN_TTL_SECONDS = '900',
    RECEIPT_TTL_SECONDS = '3600',
    REQUIRED_SCOPE = 'ai:train_data',
    USE_RECEIPT_CACHE = 'false',
    RECEIPT_CACHE_PATH = path.join('indexer', 'receipt-cache.json'),
    RECEIPT_CACHE_STALE_MS = '30000',
  } = process.env;

  if (!RPC_URL || !CONTRACT_ADDRESS || !JWT_SECRET) {
    throw new Error('Missing env: RPC_URL, CONTRACT_ADDRESS, JWT_SECRET');
  }

  const receiptClient = createViemReceiptClient({
    rpcUrl: RPC_URL,
    contractAddress: CONTRACT_ADDRESS,
  });

  const app = createBridgeApp({
    chainId: Number(CHAIN_ID),
    contractAddress: CONTRACT_ADDRESS,
    jwtSecret: JWT_SECRET,
    siweDomain: SIWE_DOMAIN,
    tokenTtlSeconds: Number(TOKEN_TTL_SECONDS),
    receiptTtlSeconds: Number(RECEIPT_TTL_SECONDS),
    requiredScope: REQUIRED_SCOPE,
    receiptClient:
      String(USE_RECEIPT_CACHE).toLowerCase() === 'true'
        ? createCachedReceiptClient({
            receiptClient,
            cachePath: RECEIPT_CACHE_PATH,
            staleMs: Number(RECEIPT_CACHE_STALE_MS),
          })
        : receiptClient,
  });

  app.listen(Number(PORT), () => {
    console.log(`OAuth bridge listening on http://localhost:${PORT}`);
  });
}

module.exports = {
  createBridgeApp,
  createNonceStore,
  createViemReceiptClient,
  createCachedReceiptClient,
  hashScope,
};
