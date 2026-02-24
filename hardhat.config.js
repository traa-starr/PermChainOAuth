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

subtask(TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD, async (args, hre, runSuper) => {
  if (args.solcVersion !== "0.8.20") {
    return runSuper();
  }

  if (!fs.existsSync(LOCAL_SOLC_METADATA_PATH)) {
    throw new Error(
      "Offline compiler cache missing. Run `node scripts/cache_compiler.js` (with internet) and commit artifacts/cache/solc."
    );
  }

  const metadata = JSON.parse(fs.readFileSync(LOCAL_SOLC_METADATA_PATH, "utf8"));
  const compilerPath = path.resolve(metadata.compilerPath);

  if (!fs.existsSync(compilerPath)) {
    throw new Error(
      `Cached compiler not found at ${compilerPath}. Rebuild cache with node scripts/cache_compiler.js.`
    );
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
