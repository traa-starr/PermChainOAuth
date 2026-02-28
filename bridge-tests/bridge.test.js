const test = require('node:test');
const assert = require('node:assert/strict');
const { createServer } = require('node:http');
const jwt = require('jsonwebtoken');
const { privateKeyToAccount } = require('viem/accounts');
const { SiweMessage } = require('siwe');

const { createBridgeApp, createNonceStore, hashScope } = require('../server');

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

async function buildSignedSiwe({ account, domain, chainId, nonce, statement }) {
  const message = new SiweMessage({
    domain,
    address: account.address,
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

test('happy path: authorize intent then token exchange with grantee SIWE', async () => {
  const granter = privateKeyToAccount('0x59c6995e998f97a5a0044966f094538f5d80e7d86f6e08f9c3f1f6ec0b3c3a9a');
  const grantee = privateKeyToAccount('0x8b3a350cf5c34c9194ca3a545d95fcae02c8d36f3d1fc0f24d6e59b8cb4f6f58');
  const now = Math.floor(Date.now() / 1000);

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

  const app = createBridgeApp({
    chainId: 11155111,
    contractAddress: '0x1111111111111111111111111111111111111111',
    jwtSecret: 'test-secret',
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

    const decoded = jwt.verify(tokenRes.data.access_token, 'test-secret');
    assert.equal(decoded.sub, granter.address);
    assert.equal(decoded.azp, grantee.address);

    const introspect = await postJson(server.url, '/introspect', {
      token: tokenRes.data.access_token,
      requiredScopeHash: hashScope('ai:train_data'),
    });

    assert.equal(introspect.status, 200);
    assert.equal(introspect.data.active, true);
    assert.equal(introspect.data.sub, granter.address);
    assert.equal(introspect.data.azp, grantee.address);
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

  const app = createBridgeApp({
    chainId: 11155111,
    contractAddress: '0x1111111111111111111111111111111111111111',
    jwtSecret: 'test-secret',
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
