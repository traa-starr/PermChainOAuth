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
