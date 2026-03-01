const test = require('node:test');
const assert = require('node:assert/strict');
const { createServer } = require('node:http');
const { generateKeyPairSync } = require('node:crypto');
const jwt = require('jsonwebtoken');
const { privateKeyToAccount } = require('viem/accounts');
const { SiweMessage } = require('siwe');

const { createBridgeApp, createNonceStore, hashScope } = require('../server');

function createJwtKeyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
  };
}

function createMockReceiptClient(initialReceipts) {
  const receipts = new Map(initialReceipts.map((r) => [Number(r.id), { ...r }]));

  return {
    receipts,
    async readReceipt(receiptId) {
      const r = receipts.get(Number(receiptId));
      if (!r) throw new Error('receipt not found');
      return { ...r };
    },
    async hasScopeHash({ receiptId, requiredScopeHash }) {
      const r = receipts.get(Number(receiptId));
      if (!r) return false;
      return r.scopeHashes.includes(requiredScopeHash);
    },
    async isValid({ receiptId, requiredScopeHash, now }) {
      const r = receipts.get(Number(receiptId));
      if (!r) return false;
      if (!r.active || r.revokedAt > 0) return false;
      if (!r.scopeHashes.includes(requiredScopeHash)) return false;
      return r.expiresAt === 0 || now <= r.expiresAt;
    },
  };
}

async function startTestServer(app) {
  const server = createServer(app);
  await new Promise((resolve) => server.listen(0, resolve));
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

async function postJson(url, path, body) {
  const response = await fetch(`${url}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await response.json();
  return { status: response.status, data };
}

async function buildSignedSiwe({ account, domain, chainId, nonce, statement, address = account.address }) {
  const message = new SiweMessage({
    domain,
    address,
    statement,
    uri: `http://${domain}`,
    version: '1',
    chainId,
    nonce,
  });
  const prepared = message.prepareMessage();
  const signature = await account.signMessage({ message: prepared });
  return { siweMessage: prepared, siweSignature: signature };
}

test('token exchange accepts checksum receipt grantee and emits normalized JWT claims', async () => {
  const granter = privateKeyToAccount('0x59c6995e998f97a5a0044966f094538f5d80e7d86f6e08f9c3f1f6ec0b3c3a9a');
  const grantee = privateKeyToAccount('0x8b3a350cf5c34c9194ca3a545d95fcae02c8d36f3d1fc0f24d6e59b8cb4f6f58');
  const now = Math.floor(Date.now() / 1000);
  assert.notEqual(grantee.address, grantee.address.toLowerCase());

  const receiptClient = createMockReceiptClient([
    {
      id: 1,
      granter: granter.address,
      grantee: grantee.address,
      scopeHashes: [hashScope('ai:train_data')],
      proofHash: hashScope('proof-1'),
      active: true,
      expiresAt: now + 3600,
      revokedAt: 0,
    },
  ]);

  const { privateKeyPem, publicKeyPem } = createJwtKeyPair();

  const app = createBridgeApp({
    chainId: 11155111,
    contractAddress: '0x1111111111111111111111111111111111111111',
    jwtAlg: 'RS256',
    jwtPrivateKeyPem: privateKeyPem,
    jwtKid: 'bridge-test-kid-a',
    siweDomain: 'localhost',
    receiptClient,
    nonceStore: createNonceStore(),
  });

  const server = await startTestServer(app);
  try {
    const authorizeNonce = await postJson(server.url, '/nonce', { address: granter.address, purpose: 'authorize' });
    const siweAuthorize = await buildSignedSiwe({
      account: granter,
      domain: 'localhost',
      chainId: 11155111,
      nonce: authorizeNonce.data.nonce,
      statement: 'authorize mint intent',
    });

    const authorizeRes = await postJson(server.url, '/authorize', {
      ...siweAuthorize,
      grantee: grantee.address,
      scopes: ['ai:train_data'],
      metadataURI: 'ipfs://x',
    });
    assert.equal(authorizeRes.status, 200);
    assert.equal(authorizeRes.data.mintIntent.granter, granter.address);

    const tokenNonce = await postJson(server.url, '/nonce', { address: grantee.address, purpose: 'token' });
    const siweToken = await buildSignedSiwe({
      account: grantee,
      domain: 'localhost',
      chainId: 11155111,
      nonce: tokenNonce.data.nonce,
      statement: 'token exchange',
    });

    const tokenRes = await postJson(server.url, '/token', {
      receiptId: 1,
      ...siweToken,
      requiredScopeHashes: [hashScope('ai:train_data')],
    });

    assert.equal(tokenRes.status, 200);
    assert.ok(tokenRes.data.access_token);

    const decodedHeader = jwt.decode(tokenRes.data.access_token, { complete: true }).header;
    assert.equal(decodedHeader.kid, 'bridge-test-kid-a');

    const decoded = jwt.verify(tokenRes.data.access_token, publicKeyPem, { algorithms: ['RS256'] });
    assert.equal(decoded.sub, granter.address.toLowerCase());
    assert.equal(decoded.azp, grantee.address.toLowerCase());

    const jwksRes = await fetch(`${server.url}/.well-known/jwks.json`);
    const jwks = await jwksRes.json();
    assert.equal(jwksRes.status, 200);
    assert.equal(Array.isArray(jwks.keys), true);
    assert.equal(jwks.keys.some((k) => k.kid === 'bridge-test-kid-a'), true);

    const introspect = await postJson(server.url, '/introspect', {
      token: tokenRes.data.access_token,
      requiredScopeHash: hashScope('ai:train_data'),
    });

    assert.equal(introspect.status, 200);
    assert.equal(introspect.data.active, true);
    assert.equal(introspect.data.sub, granter.address.toLowerCase());
    assert.equal(introspect.data.azp, grantee.address.toLowerCase());
  } finally {
    await server.close();
  }
});

test('revoke invalidates introspection', async () => {
  const granter = privateKeyToAccount('0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce037f6b6eb5adf4a6c6b09');
  const grantee = privateKeyToAccount('0x6c3699283bda56ad74f6b855546325b68d482e983852a7e4d8e9f8d9f0a5d6b1');
  const now = Math.floor(Date.now() / 1000);

  const receiptClient = createMockReceiptClient([
    {
      id: 2,
      granter: granter.address,
      grantee: grantee.address,
      scopeHashes: [hashScope('ai:train_data')],
      proofHash: hashScope('proof-1'),
      active: true,
      expiresAt: now + 3600,
      revokedAt: 0,
    },
  ]);

  const { privateKeyPem, publicKeyPem } = createJwtKeyPair();

  const app = createBridgeApp({
    chainId: 11155111,
    contractAddress: '0x1111111111111111111111111111111111111111',
    jwtAlg: 'RS256',
    jwtPrivateKeyPem: privateKeyPem,
    jwtKid: 'bridge-test-kid-a',
    siweDomain: 'localhost',
    receiptClient,
    nonceStore: createNonceStore(),
  });

  const server = await startTestServer(app);
  try {
    const tokenNonce = await postJson(server.url, '/nonce', { address: grantee.address, purpose: 'token' });
    const siweToken = await buildSignedSiwe({
      account: grantee,
      domain: 'localhost',
      chainId: 11155111,
      nonce: tokenNonce.data.nonce,
      statement: 'token exchange',
    });

    const tokenRes = await postJson(server.url, '/token', {
      receiptId: 2,
      ...siweToken,
      requiredScopeHashes: [hashScope('ai:train_data')],
    });

    receiptClient.receipts.get(2).active = false;
    receiptClient.receipts.get(2).revokedAt = Math.floor(Date.now() / 1000);

    const introspect = await postJson(server.url, '/introspect', {
      token: tokenRes.data.access_token,
      requiredScopeHash: hashScope('ai:train_data'),
    });

    assert.equal(introspect.status, 200);
    assert.equal(introspect.data.active, false);
  } finally {
    await server.close();
  }
});

test('rotation keeps old kid verifiable via jwtPublicKeysJson', async () => {
  const granter = privateKeyToAccount('0x59c6995e998f97a5a0044966f094538f5d80e7d86f6e08f9c3f1f6ec0b3c3a9a');
  const grantee = privateKeyToAccount('0x8b3a350cf5c34c9194ca3a545d95fcae02c8d36f3d1fc0f24d6e59b8cb4f6f58');
  const now = Math.floor(Date.now() / 1000);
  const receiptClient = createMockReceiptClient([
    {
      id: 3,
      granter: granter.address,
      grantee: grantee.address,
      scopeHashes: [hashScope('ai:train_data')],
      proofHash: hashScope('proof-3'),
      active: true,
      expiresAt: now + 3600,
      revokedAt: 0,
    },
  ]);

  const keyA = createJwtKeyPair();
  const appA = createBridgeApp({
    chainId: 11155111,
    contractAddress: '0x1111111111111111111111111111111111111111',
    jwtAlg: 'RS256',
    jwtPrivateKeyPem: keyA.privateKeyPem,
    jwtKid: 'kid-a',
    siweDomain: 'localhost',
    receiptClient,
    nonceStore: createNonceStore(),
  });

  const serverA = await startTestServer(appA);
  let issuedToken;
  try {
    const tokenNonce = await postJson(serverA.url, '/nonce', { address: grantee.address, purpose: 'token' });
    const siweToken = await buildSignedSiwe({
      account: grantee,
      domain: 'localhost',
      chainId: 11155111,
      nonce: tokenNonce.data.nonce,
      statement: 'token exchange',
    });

    const tokenRes = await postJson(serverA.url, '/token', {
      receiptId: 3,
      ...siweToken,
      requiredScopeHashes: [hashScope('ai:train_data')],
    });

    assert.equal(tokenRes.status, 200);
    issuedToken = tokenRes.data.access_token;
    assert.equal(jwt.decode(issuedToken, { complete: true }).header.kid, 'kid-a');
  } finally {
    await serverA.close();
  }

  const keyB = createJwtKeyPair();
  const appB = createBridgeApp({
    chainId: 11155111,
    contractAddress: '0x1111111111111111111111111111111111111111',
    jwtAlg: 'RS256',
    jwtPrivateKeyPem: keyB.privateKeyPem,
    jwtKid: 'kid-b',
    jwtPublicKeysJson: [{ kid: 'kid-a', publicKeyPem: keyA.publicKeyPem }],
    siweDomain: 'localhost',
    receiptClient,
    nonceStore: createNonceStore(),
  });

  const serverB = await startTestServer(appB);
  try {
    const introspect = await postJson(serverB.url, '/introspect', {
      token: issuedToken,
      requiredScopeHash: hashScope('ai:train_data'),
    });

    assert.equal(introspect.status, 200);
    assert.equal(introspect.data.active, true);

    const jwksRes = await fetch(`${serverB.url}/.well-known/jwks.json`);
    const jwks = await jwksRes.json();
    assert.equal(jwks.keys.some((k) => k.kid === 'kid-a'), true);
    assert.equal(jwks.keys.some((k) => k.kid === 'kid-b'), true);
  } finally {
    await serverB.close();
  }
});
