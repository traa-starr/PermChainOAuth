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

function readCache(filePath) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    const parsed = JSON.parse(raw);
    return {
      meta: { ...DEFAULT_CACHE.meta, ...(parsed.meta || {}) },
      receipts: parsed.receipts || {},
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
  };
  fs.writeFileSync(filePath, `${JSON.stringify(next, null, 2)}\n`, 'utf8');
  return next;
}

module.exports = {
  readCache,
  writeCache,
};
