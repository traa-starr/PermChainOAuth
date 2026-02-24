#!/usr/bin/env node

const fs = require("fs");
const path = require("path");

const CACHE_DIR = path.join(process.cwd(), "artifacts", "cache", "solc");
const METADATA_PATH = path.join(CACHE_DIR, "solc-build.json");

const REMEDIATION = [
  "Offline Solidity cache is missing or incomplete.",
  "Remediation (run on an ONLINE machine):",
  "  npm ci && npm run cache:solc",
  "Then commit these files:",
  "  artifacts/cache/solc/list.json",
  "  artifacts/cache/solc/<soljson file>",
  "  artifacts/cache/solc/solc-build.json",
].join("\n");

function fail(reason) {
  console.error(`\n${reason}\n\n${REMEDIATION}\n`);
  process.exit(1);
}

if (!fs.existsSync(METADATA_PATH)) {
  fail(`Missing ${path.relative(process.cwd(), METADATA_PATH)}.`);
}

let metadata;
try {
  metadata = JSON.parse(fs.readFileSync(METADATA_PATH, "utf8"));
} catch (error) {
  fail(`Invalid JSON in ${path.relative(process.cwd(), METADATA_PATH)}: ${error.message}`);
}

if (!metadata || typeof metadata !== "object" || !metadata.fileName) {
  fail("solc-build.json must contain a 'fileName' field.");
}

const listPath = path.join(CACHE_DIR, "list.json");
if (!fs.existsSync(listPath)) {
  fail(`Missing ${path.relative(process.cwd(), listPath)}.`);
}

const compilerPath = path.join(CACHE_DIR, metadata.fileName);
if (!fs.existsSync(compilerPath)) {
  fail(`Missing compiler file ${path.relative(process.cwd(), compilerPath)} referenced by solc-build.json.`);
}

console.log(`Using offline Solidity compiler cache from ${path.relative(process.cwd(), CACHE_DIR)}.`);
