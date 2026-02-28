const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Module = require('node:module');

const ZERO_SCOPE_HASH = `0x${'0'.repeat(64)}`;

function loadServerWithMockedViem(mockCreatePublicClient) {
  const serverPath = require.resolve('../server');
  const originalLoad = Module._load;
  const viem = require('viem');

  Module._load = function patchedLoad(request, parent, isMain) {
    if (request === 'viem') {
      return {
        ...viem,
        createPublicClient: mockCreatePublicClient,
      };
    }
    return originalLoad.apply(this, arguments);
  };

  delete require.cache[serverPath];
  const serverModule = require('../server');

  Module._load = originalLoad;
  delete require.cache[serverPath];

  return serverModule;
}

test('createViemReceiptClient.readReceipt does not call getScopeHashes for non-existent receipts', async () => {
  const calls = [];
  const mockClient = {
    readContract({ functionName }) {
      calls.push(functionName);
      if (functionName === 'receipts') {
        return Promise.resolve([
          '0x0000000000000000000000000000000000000000',
          '0x0000000000000000000000000000000000000000',
          ZERO_SCOPE_HASH,
          0n,
          0n,
          0n,
          false,
          false,
        ]);
      }
      throw new Error('getScopeHashes should not be called for non-existent receipt');
    },
  };

  const { createViemReceiptClient } = loadServerWithMockedViem(() => mockClient);
  const client = createViemReceiptClient({
    rpcUrl: 'http://127.0.0.1:8545',
    contractAddress: '0x1111111111111111111111111111111111111111',
  });

  const receipt = await client.readReceipt(42);
  assert.deepEqual(calls, ['receipts']);
  assert.equal(receipt.exists, false);
  assert.deepEqual(receipt.scopeHashes, []);
});

test('createCachedReceiptClient.isValid treats zero scope hash as bypass', async () => {
  const { createCachedReceiptClient } = require('../server');
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'receipt-cache-test-'));
  const cachePath = path.join(tempDir, 'cache.json');

  const cachedClient = createCachedReceiptClient({
    cachePath,
    staleMs: 10_000,
    receiptClient: {
      async readReceipt() {
        return {
          granter: '0x1111111111111111111111111111111111111111',
          grantee: '0x2222222222222222222222222222222222222222',
          proofHash: ZERO_SCOPE_HASH,
          issuedAt: 0,
          expiresAt: 0,
          revokedAt: 0,
          active: true,
          exists: true,
          scopeHashes: [],
        };
      },
    },
  });

  await cachedClient.refreshReceipt(7);

  const valid = await cachedClient.isValid({
    receiptId: 7,
    requiredScopeHash: ZERO_SCOPE_HASH,
    now: Math.floor(Date.now() / 1000),
  });

  assert.equal(valid, true);
});
