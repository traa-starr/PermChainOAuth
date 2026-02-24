#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const https = require("https");

const SOLC_VERSION = process.env.SOLC_VERSION || "0.8.20";
const SOLC_BASE_URL = process.env.SOLC_BASE_URL || "https://binaries.soliditylang.org/bin";
const CACHE_ROOT = process.env.SOLC_CACHE_DIR || path.join(process.cwd(), "artifacts", "cache", "solc");
const LIST_FILE = path.join(CACHE_ROOT, "list.json");

function download(url) {
  return new Promise((resolve, reject) => {
    https
      .get(url, (response) => {
        if (
          response.statusCode >= 300 &&
          response.statusCode < 400 &&
          response.headers.location
        ) {
          response.resume();
          return resolve(download(response.headers.location));
        }

        if (response.statusCode !== 200) {
          response.resume();
          return reject(new Error(`Failed to fetch ${url} (HTTP ${response.statusCode})`));
        }

        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => resolve(Buffer.concat(chunks)));
      })
      .on("error", reject);
  });
}

function removeExtraFiles(cacheRoot, allowedFileNames) {
  for (const entry of fs.readdirSync(cacheRoot, { withFileTypes: true })) {
    const entryPath = path.join(cacheRoot, entry.name);
    if (entry.isDirectory()) {
      fs.rmSync(entryPath, { recursive: true, force: true });
      continue;
    }

    if (!allowedFileNames.has(entry.name)) {
      fs.rmSync(entryPath, { force: true });
    }
  }
}

async function main() {
  fs.mkdirSync(CACHE_ROOT, { recursive: true });

  const listUrl = `${SOLC_BASE_URL}/list.json`;
  console.log(`Fetching ${listUrl}`);
  const listBuffer = await download(listUrl);
  fs.writeFileSync(LIST_FILE, listBuffer);

  const list = JSON.parse(listBuffer.toString("utf8"));
  // Prefer the *released* compiler for SOLC_VERSION.
  // Nightly/pre-release builds are semver-lower than the release and will fail
  // on pragmas like `^0.8.20` (OpenZeppelin v5 uses this).
  let build;

  const releasePath = list?.releases?.[SOLC_VERSION];
  if (releasePath) {
    build = list.builds.find((entry) => entry.path === releasePath);
  } else {
    const candidates = (list.builds || []).filter((entry) => entry.version === SOLC_VERSION);
    build =
      candidates.find(
        (entry) =>
          !String(entry.longVersion || "").includes("nightly") &&
          !String(entry.path || "").includes("nightly") &&
          !String(entry.longVersion || "").includes("-")
      ) ||
      candidates.find(
        (entry) =>
          !String(entry.longVersion || "").includes("nightly") &&
          !String(entry.path || "").includes("nightly")
      ) ||
      candidates[0];
  }

  if (!build) {
    throw new Error(`Version ${SOLC_VERSION} not found in ${listUrl}`);
  }

  if (String(build.longVersion || "").includes("nightly") || String(build.path || "").includes("nightly")) {
    throw new Error(
      `Resolved ${SOLC_VERSION} to a nightly/pre-release build (${build.longVersion || build.path}).
` +
        `This repo requires the released ${SOLC_VERSION} compiler (e.g. soljson-v${SOLC_VERSION}+commit.*.js).
` +
        `If you're online, re-run: npm run cache:solc`
    );
  }

  const compilerUrl = `${SOLC_BASE_URL}/${build.path}`;
  const compilerPath = path.join(CACHE_ROOT, build.path);

  console.log(`Fetching ${compilerUrl}`);
  const compilerBuffer = await download(compilerUrl);
  fs.writeFileSync(compilerPath, compilerBuffer);

  const metadataPath = path.join(CACHE_ROOT, "solc-build.json");
  fs.writeFileSync(
    metadataPath,
    JSON.stringify(
      {
        version: build.version,
        longVersion: build.longVersion,
        fileName: build.path,
      },
      null,
      2
    )
  );

  removeExtraFiles(CACHE_ROOT, new Set(["list.json", build.path, "solc-build.json"]));

  console.log("Compiler cache updated:");
  console.log(`- list: ${LIST_FILE}`);
  console.log(`- compiler: ${compilerPath}`);
  console.log(`- metadata: ${metadataPath}`);
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
