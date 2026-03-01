require('dotenv').config();

const express = require('express');
const jwt = require('jsonwebtoken');
const path = require('path');
const { createPublicKey, createHash } = require('node:crypto');
const { SiweMessage, generateNonce } = require('siwe');
const { createPublicClient, http, parseAbi, getAddress, keccak256, toBytes, isAddress } = require('viem');
const { readCache, writeCache } = require('./indexer/cacheStore');

const DEFAULT_CHAIN_ID = 11155111;
const SCOPE_HASH_DOMAIN = 'PERMCHAIN_SCOPE_V1:';
const ZERO_SCOPE_HASH = `0x${'0'.repeat(64)}`;

function normalizeAddress(addr) {
  if (typeof addr !== 'string') return addr;
  return addr.toLowerCase();
}

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

function toBase64Url(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function computeJktFromJwk(jwk) {
  if (!jwk || typeof jwk !== 'object' || !jwk.kty) {
    throw new Error('Invalid DPoP JWK');
  }

  let members;
  if (jwk.kty === 'RSA') {
    members = { e: jwk.e, kty: jwk.kty, n: jwk.n };
  } else if (jwk.kty === 'EC') {
    members = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  } else if (jwk.kty === 'OKP') {
    members = { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
  } else {
    throw new Error(`Unsupported DPoP JWK kty: ${jwk.kty}`);
  }

  if (Object.values(members).some((value) => typeof value !== 'string' || value.length === 0)) {
    throw new Error('Invalid DPoP JWK members');
  }

  const canonical = JSON.stringify(members);
  const digest = createHash('sha256').update(canonical).digest();
  return toBase64Url(digest);
}

function createDpopReplayStore({ ttlSeconds }) {
  const entries = new Map();
  const ttlMs = Math.max(1, Number(ttlSeconds || 120)) * 1000;

  function prune(nowMs) {
    for (const [key, expiresAt] of entries) {
      if (expiresAt <= nowMs) entries.delete(key);
    }
  }

  return {
    assertNotSeen({ jti, jkt }) {
      const nowMs = Date.now();
      prune(nowMs);
      const key = `${String(jkt)}:${String(jti)}`;
      if (entries.has(key)) {
        throw new Error('DPoP replay detected');
      }
      entries.set(key, nowMs + ttlMs);
    },
  };
}

function canonicalizeHtu(req) {
  return `${req.protocol}://${req.get('host')}${req.path}`;
}

function verifyDpop(dpopJwt, expected) {
  const decoded = jwt.decode(dpopJwt, { complete: true });
  if (!decoded || !decoded.header || !decoded.payload) {
    throw new Error('Invalid DPoP JWT');
  }
  const jwk = decoded.header.jwk;
  if (!jwk) throw new Error('Missing DPoP JWK header');
  const computedJkt = computeJktFromJwk(jwk);
  if (computedJkt !== expected.cnfJkt) {
    throw new Error('DPoP JWK thumbprint mismatch');
  }

  const publicKey = createPublicKey({ key: jwk, format: 'jwk' });
  const verified = jwt.verify(dpopJwt, publicKey, {
    algorithms: ['RS256', 'ES256', 'ES384', 'ES512', 'EdDSA'],
  });

  const { htm, htu, iat, jti } = verified;
  if (!htm || !htu || !iat || !jti) throw new Error('Missing DPoP claims');
  if (String(htm).toUpperCase() !== String(expected.htm).toUpperCase()) {
    throw new Error('DPoP htm mismatch');
  }
  if (String(htu) !== String(expected.htu)) {
    throw new Error('DPoP htu mismatch');
  }

  const now = Math.floor(Date.now() / 1000);
  const maxSkewSeconds = Number(expected.maxSkewSeconds || 60);
  if (Math.abs(now - Number(iat)) > maxSkewSeconds) {
    throw new Error('DPoP iat outside allowed skew');
  }

  return { jti: String(jti), jkt: computedJkt, payload: verified };
}

function createViemReceiptClient({ rpcUrl, contractAddress }) {
  const client = createPublicClient({ transport: http(rpcUrl) });
  const address = getAddress(contractAddress);
  const abi = parseAbi([
    'function receipts(uint256 tokenId) view returns (address granter,address grantee,bytes32 proofHash,uint64 issuedAt,uint64 expiresAt,uint64 revokedAt,bool active,bool exists)',
    'function getScopeHashes(uint256 tokenId) view returns (bytes32[])',
    'function mint(address grantee,bytes32[] scopeHashes,string metadataURI,bytes32 proofHash,uint64 expiresAt) returns (uint256)',
    'function isValid(uint256 tokenId,bytes32 requiredScopeHash,uint64 timestamp) view returns (bool)',
    'function hasScopeHash(uint256 tokenId,bytes32 scopeHash) view returns (bool)',
  ]);

  async function readReceipt(receiptId) {
    const raw = await client.readContract({
      address,
      abi,
      functionName: 'receipts',
      args: [BigInt(receiptId)],
    });

    const exists = Boolean(raw[7]);
    if (!exists) {
      return {
        granter: normalizeAddress(raw[0]),
        grantee: normalizeAddress(raw[1]),
        proofHash: String(raw[2]),
        issuedAt: Number(raw[3]),
        expiresAt: Number(raw[4]),
        revokedAt: Number(raw[5]),
        active: Boolean(raw[6]),
        exists: false,
        scopeHashes: [],
      };
    }

    const scopeHashes = await client.readContract({
      address,
      abi,
      functionName: 'getScopeHashes',
      args: [BigInt(receiptId)],
    });

    return {
      granter: normalizeAddress(raw[0]),
      grantee: normalizeAddress(raw[1]),
      proofHash: String(raw[2]),
      issuedAt: Number(raw[3]),
      expiresAt: Number(raw[4]),
      revokedAt: Number(raw[5]),
      active: Boolean(raw[6]),
      exists,
      scopeHashes: scopeHashes.map(String),
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
    const bypassScopeCheck =
      !requiredScopeHash || String(requiredScopeHash).toLowerCase() === ZERO_SCOPE_HASH;
    const { entry } = getCachedEntry(receiptId);
    if (entry) {
      const notRevoked = Boolean(entry.active) && Number(entry.revokedAt || 0) === 0;
      const notExpired = Number(entry.expiresAt || 0) === 0 || now <= Number(entry.expiresAt);
      const hasRequiredScope = bypassScopeCheck || entry.scopeHashes.includes(requiredScopeHash);

      if (Date.now() - Number(entry.updatedAt || 0) <= staleMs) {
        return notRevoked && notExpired && hasRequiredScope;
      }
    }

    const refreshed = await refreshReceipt(receiptId);
    const notRevoked = Boolean(refreshed.active) && Number(refreshed.revokedAt || 0) === 0;
    const notExpired = Number(refreshed.expiresAt || 0) === 0 || now <= Number(refreshed.expiresAt);
    const hasRequiredScope = bypassScopeCheck || refreshed.scopeHashes.includes(requiredScopeHash);
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
  jwtAlg = 'RS256',
  jwtPrivateKeyPem,
  jwtKid,
  jwtPublicKeysJson = [],
  siweDomain = 'localhost',
  tokenTtlSeconds = 900,
  receiptTtlSeconds = 3600,
  requiredScope = 'ai:train_data',
  receiptClient,
  nonceStore = createNonceStore(),
  popRequired = false,
  popNonceTtlSeconds = 120,
}) {
  const normalizedJwtAlg = String(jwtAlg || 'RS256').toUpperCase();
  if (normalizedJwtAlg === 'RS256') {
    if (!Array.isArray(jwtPublicKeysJson)) throw new Error('jwtPublicKeysJson must be an array');
    if (!jwtPrivateKeyPem) throw new Error('jwtPrivateKeyPem is required when jwtAlg=RS256');
    if (!jwtKid) throw new Error('jwtKid is required when jwtAlg=RS256');
  } else if (!jwtSecret) {
    throw new Error('jwtSecret is required when jwtAlg is not RS256');
  }
  if (!contractAddress) throw new Error('contractAddress is required');
  if (!receiptClient) throw new Error('receiptClient is required');

  const verificationKeys = new Map();
  const jwksKeys = [];
  const dpopReplayStore = createDpopReplayStore({ ttlSeconds: popNonceTtlSeconds });

  function pushJwkFromPublicPem({ kid, publicKeyPem }) {
    const jwk = createPublicKey(publicKeyPem).export({ format: 'jwk' });
    jwksKeys.push({
      ...jwk,
      kid,
      use: 'sig',
      alg: normalizedJwtAlg,
    });
  }

  if (normalizedJwtAlg === 'RS256') {
    const activePublicKeyPem = createPublicKey(jwtPrivateKeyPem).export({ type: 'spki', format: 'pem' });
    verificationKeys.set(String(jwtKid), activePublicKeyPem);
    pushJwkFromPublicPem({ kid: String(jwtKid), publicKeyPem: activePublicKeyPem });

    for (const keyEntry of jwtPublicKeysJson || []) {
      if (!keyEntry || !keyEntry.kid || !keyEntry.publicKeyPem) continue;
      const keyId = String(keyEntry.kid);
      if (verificationKeys.has(keyId)) continue;
      verificationKeys.set(keyId, keyEntry.publicKeyPem);
      pushJwkFromPublicPem({ kid: keyId, publicKeyPem: keyEntry.publicKeyPem });
    }
  }

  function verifyTokenSignature(token) {
    if (normalizedJwtAlg === 'RS256') {
      const decoded = jwt.decode(token, { complete: true });
      const tokenKid = decoded && decoded.header && decoded.header.kid;
      if (!tokenKid) throw new Error('Missing kid in JWT header');
      const publicKeyPem = verificationKeys.get(String(tokenKid));
      if (!publicKeyPem) throw new Error('Unknown kid');
      return jwt.verify(token, publicKeyPem, { algorithms: [normalizedJwtAlg] });
    }
    return jwt.verify(token, jwtSecret, { algorithms: [normalizedJwtAlg] });
  }

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
          mintFunction: 'mint(address grantee, bytes32[] scopeHashes, string metadataURI, bytes32 proofHash, uint64 expiresAt)',
          note: 'User wallet must submit mint transaction. granter is inferred as msg.sender on-chain.',
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
        dpopJwk,
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
      if (normalizeAddress(siweAddress) !== normalizeAddress(receipt.grantee)) {
        return res.status(403).json({ error: 'SIWE signer must match receipt grantee' });
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

      if (Boolean(popRequired) && !dpopJwk) {
        return res.status(400).json({ error: 'dpopJwk is required when POP_REQUIRED=true' });
      }

      let cnf;
      if (dpopJwk) {
        cnf = { jkt: computeJktFromJwk(dpopJwk) };
      }

      const jwtExp = Math.min(now + Number(tokenTtlSeconds), receipt.expiresAt || now + Number(tokenTtlSeconds));
      const payload = {
        sub: normalizeAddress(receipt.granter),
        azp: normalizeAddress(receipt.grantee),
        receiptId: Number(receiptId),
        scopeHashes: receipt.scopeHashes,
        iat: now,
        exp: jwtExp,
        aud,
        iss: `permchain-oauth:${Number(chainId)}`,
        chainId: Number(chainId),
        ...(cnf ? { cnf } : {}),
      };
      const signOptions = normalizedJwtAlg === 'RS256'
        ? { algorithm: normalizedJwtAlg, header: { kid: String(jwtKid), alg: normalizedJwtAlg, typ: 'JWT' } }
        : { algorithm: normalizedJwtAlg };
      const signingKey = normalizedJwtAlg === 'RS256' ? jwtPrivateKeyPem : jwtSecret;
      const accessToken = jwt.sign(payload, signingKey, signOptions);

      return res.json({ token_type: 'Bearer', expires_in: Math.max(0, jwtExp - now), access_token: accessToken });
    } catch (error) {
      return res.status(400).json({ error: error.message });
    }
  });

  async function introspectToken(token, requiredScopeHash = hashScope(requiredScope)) {
    try {
      const decoded = verifyTokenSignature(token);
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
        azp: decoded.azp,
        scopeHashes: decoded.scopeHashes,
        exp: decoded.exp,
        receiptId: decoded.receiptId,
        aud: decoded.aud,
        iss: decoded.iss,
        cnf: decoded.cnf,
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

  app.get('/.well-known/jwks.json', (_req, res) => {
    if (normalizedJwtAlg !== 'RS256') {
      return res.json({ keys: [] });
    }
    return res.json({ keys: jwksKeys });
  });

  app.get('/data', async (req, res) => {
    const authz = req.headers.authorization || '';
    const token = authz.startsWith('Bearer ') ? authz.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Missing bearer token' });

    const result = await introspectToken(token, hashScope(requiredScope));
    if (!result.active) {
      return res.status(Boolean(popRequired) ? 401 : 403).json({ error: 'Token inactive for required scope' });
    }

    if (Boolean(popRequired)) {
      const dpopHeader = req.get('dpop');
      if (!dpopHeader) return res.status(401).json({ error: 'Missing DPoP proof' });
      if (!result.cnf || !result.cnf.jkt) return res.status(401).json({ error: 'Token missing cnf.jkt' });

      try {
        const proof = verifyDpop(dpopHeader, {
          htm: req.method,
          htu: canonicalizeHtu(req),
          cnfJkt: result.cnf.jkt,
        });
        dpopReplayStore.assertNotSeen({ jti: proof.jti, jkt: proof.jkt });
      } catch (error) {
        return res.status(401).json({ error: error.message });
      }
    }

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
    JWT_ALG = 'RS256',
    JWT_PRIVATE_KEY_PEM,
    JWT_KID,
    JWT_PUBLIC_KEYS_JSON = '[]',
    SIWE_DOMAIN = 'localhost',
    TOKEN_TTL_SECONDS = '900',
    RECEIPT_TTL_SECONDS = '3600',
    POP_REQUIRED = 'false',
    POP_NONCE_TTL_SECONDS = '120',
    REQUIRED_SCOPE = 'ai:train_data',
    USE_RECEIPT_CACHE = 'false',
    RECEIPT_CACHE_PATH = path.join('indexer', 'receipt-cache.json'),
    RECEIPT_CACHE_STALE_MS = '30000',
  } = process.env;

  if (!RPC_URL || !CONTRACT_ADDRESS) {
    throw new Error('Missing env: RPC_URL, CONTRACT_ADDRESS');
  }

  let parsedPublicKeys;
  try {
    parsedPublicKeys = JSON.parse(JWT_PUBLIC_KEYS_JSON);
  } catch (error) {
    throw new Error(`Invalid JWT_PUBLIC_KEYS_JSON: ${error.message}`);
  }

  const receiptClient = createViemReceiptClient({
    rpcUrl: RPC_URL,
    contractAddress: CONTRACT_ADDRESS,
  });

  const app = createBridgeApp({
    chainId: Number(CHAIN_ID),
    contractAddress: CONTRACT_ADDRESS,
    jwtSecret: JWT_SECRET,
    jwtAlg: JWT_ALG,
    jwtPrivateKeyPem: JWT_PRIVATE_KEY_PEM,
    jwtKid: JWT_KID,
    jwtPublicKeysJson: parsedPublicKeys,
    siweDomain: SIWE_DOMAIN,
    tokenTtlSeconds: Number(TOKEN_TTL_SECONDS),
    receiptTtlSeconds: Number(RECEIPT_TTL_SECONDS),
    popRequired: String(POP_REQUIRED).toLowerCase() === 'true',
    popNonceTtlSeconds: Number(POP_NONCE_TTL_SECONDS),
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
  createReceiptClient: createViemReceiptClient,
  createViemReceiptClient,
  createCachedReceiptClient,
  normalizeAddress,
  computeJktFromJwk,
  verifyDpop,
  hashScope,
  SCOPE_HASH_DOMAIN,
};
