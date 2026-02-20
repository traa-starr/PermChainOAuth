const hre = require("hardhat");

async function main() {
  const PermissionReceipt = await hre.ethers.getContractFactory("PermissionReceipt");
  const permissionReceipt = await PermissionReceipt.deploy();
  await permissionReceipt.waitForDeployment();

  console.log("PermissionReceipt deployed to:", await permissionReceipt.getAddress());
  console.log(
    "ABI is available at artifacts/contracts/PermissionReceipt.sol/PermissionReceipt.json"
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
