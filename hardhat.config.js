require("@nomicfoundation/hardhat-toolbox");
const fs = require("fs");
const path = require("path");
const {
  TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD,
} = require("hardhat/builtin-tasks/task-names");

const TEST_MNEMONIC =
  process.env.TEST_MNEMONIC || "test test test test test test test test test test test junk";
const LOCAL_SOLC_CACHE_DIR = path.join(__dirname, "artifacts", "cache", "solc");
const LOCAL_SOLC_METADATA_PATH = path.join(LOCAL_SOLC_CACHE_DIR, "solc-build.json");

function cacheError(reason) {
  return new Error(
    `${reason}\n\nOffline Solidity cache is required for this repository.\n` +
      "Remediation (run on an ONLINE machine):\n" +
      "  npm ci && npm run cache:solc\n" +
      "Then commit artifacts/cache/solc/{list.json,<soljson file>,solc-build.json}."
  );
}

subtask(TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD, async (args, hre, runSuper) => {
  if (args.solcVersion !== "0.8.20") {
    return runSuper();
  }

  if (!fs.existsSync(LOCAL_SOLC_METADATA_PATH)) {
    throw cacheError(`Missing ${path.relative(__dirname, LOCAL_SOLC_METADATA_PATH)}.`);
  }

  let metadata;
  try {
    metadata = JSON.parse(fs.readFileSync(LOCAL_SOLC_METADATA_PATH, "utf8"));
  } catch (error) {
    throw cacheError(`Invalid JSON in ${path.relative(__dirname, LOCAL_SOLC_METADATA_PATH)}: ${error.message}`);
  }

  if (!metadata.fileName) {
    throw cacheError("Invalid solc-build.json: expected 'fileName'.");
  }

  const compilerPath = path.join(LOCAL_SOLC_CACHE_DIR, metadata.fileName);
  if (!fs.existsSync(compilerPath)) {
    throw cacheError(
      `Missing compiler file ${path.relative(__dirname, compilerPath)} referenced by solc-build.json.`
    );
  }

  const listPath = path.join(LOCAL_SOLC_CACHE_DIR, "list.json");
  if (!fs.existsSync(listPath)) {
    throw cacheError(`Missing ${path.relative(__dirname, listPath)}.`);
  }

  return {
    version: metadata.version,
    longVersion: metadata.longVersion,
    compilerPath,
    isSolcJs: true,
  };
});

module.exports = {
  solidity: {
    version: "0.8.20",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
  networks: {
    hardhat: {
      chainId: 31337,
      accounts: {
        mnemonic: TEST_MNEMONIC,
        count: 10,
      },
    },
    sepolia: {
      url: process.env.ALCHEMY_SEPOLIA_RPC_URL || "https://eth-sepolia.g.alchemy.com/v2/YOUR_ALCHEMY_API_KEY",
      accounts: process.env.DEPLOYER_PRIVATE_KEY ? [process.env.DEPLOYER_PRIVATE_KEY] : [],
    },
  },
};
