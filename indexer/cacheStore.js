const fs = require('fs');
const path = require('path');

const DEFAULT_CACHE = {
  meta: {
    updatedAt: 0,
    chainId: null,
    contractAddress: null,
    lastIndexedBlock: 0,
  },
  receipts: {},
};

function ensureParent(filePath) {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true });
}

function normalizeReceipts(receipts = {}) {
  return Object.fromEntries(
    Object.entries(receipts).map(([tokenId, receipt]) => [
      tokenId,
      {
        ...receipt,
        tokenId: receipt?.tokenId ?? Number(tokenId),
        scopeHashes: Array.isArray(receipt?.scopeHashes) ? receipt.scopeHashes : [],
      },
    ])
  );
}

function readCache(filePath) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    const parsed = JSON.parse(raw);
    return {
      meta: { ...DEFAULT_CACHE.meta, ...(parsed.meta || {}) },
      receipts: normalizeReceipts(parsed.receipts || {}),
    };
  } catch {
    return { ...DEFAULT_CACHE, receipts: {} };
  }
}

function writeCache(filePath, data) {
  ensureParent(filePath);
  const next = {
    ...data,
    meta: {
      ...DEFAULT_CACHE.meta,
      ...(data.meta || {}),
      updatedAt: Date.now(),
    },
    receipts: normalizeReceipts(data.receipts || {}),
  };
  fs.writeFileSync(filePath, `${JSON.stringify(next, null, 2)}\n`, 'utf8');
  return next;
}

module.exports = {
  readCache,
  writeCache,
};
