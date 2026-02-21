const hre = require("hardhat");

async function main() {
  const PermissionReceipt = await hre.ethers.getContractFactory("PermissionReceipt");
  const permissionReceipt = await PermissionReceipt.deploy();
  await permissionReceipt.waitForDeployment();

  const address = await permissionReceipt.getAddress();

  console.log(`PermissionReceipt deployed on ${hre.network.name}: ${address}`);
  console.log("ABI: artifacts/contracts/PermissionReceipt.sol/PermissionReceipt.json");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
