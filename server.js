require('dotenv').config();

const express = require('express');
const jwt = require('jsonwebtoken');
const { SiweMessage, generateNonce } = require('siwe');
const { createPublicClient, http, parseAbi, getAddress, keccak256, toBytes, isAddress } = require('viem');

const DEFAULT_CHAIN_ID = 11155111;
const SCOPE_HASH_DOMAIN = 'PERMCHAIN_SCOPE_V1:';

function hashScope(scope) {
  return keccak256(toBytes(`${SCOPE_HASH_DOMAIN}${String(scope)}`));
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
    'function receipts(uint256 tokenId) view returns (address granter,address grantee,string scope,string proofHash,uint256 issuedAt,uint256 expiresAt,uint256 revokedAt,bool active)',
    'function isValid(uint256 tokenId,bytes32 scopeHash,uint256 timestamp) view returns (bool)',
    'function hasScopeHash(uint256 tokenId,bytes32 scopeHash) view returns (bool)',
    'function isRevoked(uint256 tokenId) view returns (bool)',
    'function isExpired(uint256 tokenId) view returns (bool)',
  ]);

  async function readReceipt(receiptId) {
    const raw = await client.readContract({
      address,
      abi,
      functionName: 'receipts',
      args: [BigInt(receiptId)],
    });

    const scopeHashes = [hashScope(raw[2])];
    return {
      receiptId: Number(receiptId),
      granter: getAddress(raw[0]),
      grantee: getAddress(raw[1]),
      scope: String(raw[2]),
      scopeHashes,
      proofHash: String(raw[3]),
      issuedAt: Number(raw[4]),
      expiresAt: Number(raw[5]),
      revokedAt: Number(raw[6]),
      active: Boolean(raw[7]),
    };
  }

  async function isValid({ receiptId, requiredScopeHash, now }) {
    try {
      return await client.readContract({
        address,
        abi,
        functionName: 'isValid',
        args: [BigInt(receiptId), requiredScopeHash, BigInt(now)],
      });
    } catch {
      const receipt = await readReceipt(receiptId);
      if (!receipt.active || receipt.revokedAt > 0) return false;
      if (!receipt.scopeHashes.includes(requiredScopeHash)) return false;
      return receipt.expiresAt === 0 || now <= receipt.expiresAt;
    }
  }

  return { readReceipt, isValid };
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
      const { siweMessage, siweSignature, grantee, scopes = [], metadataURI = '', expiresAt } = req.body || {};
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

      return res.json({
        mintIntent: {
          contractAddress: getAddress(contractAddress),
          chainId: Number(chainId),
          granter,
          grantee: getAddress(grantee),
          scopeHashes,
          expiresAt: resolvedExpiresAt,
          proofHash,
          metadataURI,
          mintFunction: 'mint(address grantee, bytes32[] scopeHashes, string metadataURI, bytes32 proofHash, uint256 expiresAt)',
          note: 'User wallet must submit mint transaction. granter is msg.sender on-chain.',
        },
      });
    } catch (error) {
      return res.status(400).json({ error: error.message });
    }
  });

  app.post('/token', async (req, res) => {
    try {
      const { receiptId, siweMessage, siweSignature, requiredScopeHashes = [hashScope(requiredScope)] } = req.body || {};
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
        scope: decoded.scopeHashes.join(' '),
        exp: decoded.exp,
        receiptId: decoded.receiptId,
        granter: decoded.granter,
        grantee: decoded.grantee,
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
    receiptClient,
  });

  app.listen(Number(PORT), () => {
    console.log(`OAuth bridge listening on http://localhost:${PORT}`);
  });
}

module.exports = {
  createBridgeApp,
  createNonceStore,
  createViemReceiptClient,
  hashScope,
};
