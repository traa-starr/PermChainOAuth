require("@nomicfoundation/hardhat-toolbox");

const TEST_MNEMONIC =
  process.env.TEST_MNEMONIC || "test test test test test test test test test test test junk";

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
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts",
  },
  networks: {
    hardhat: {
      chainId: 31337,
      accounts: {
        mnemonic: TEST_MNEMONIC,
        count: 10,
      },
    },
  },
};
