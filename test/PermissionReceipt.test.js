const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("PermissionReceipt", function () {
  async function deployFixture() {
    const [granter, grantee, other] = await ethers.getSigners();
    const PermissionReceipt = await ethers.getContractFactory("PermissionReceipt");
    const permissionReceipt = await PermissionReceipt.deploy();
    await permissionReceipt.waitForDeployment();

    return { permissionReceipt, granter, grantee, other };
  }

  it("mints a receipt, emits an event, and stores receipt data", async function () {
    const { permissionReceipt, granter, grantee } = await deployFixture();

    const scope = "read:reports";
    const tokenURI = "ipfs://permission-receipt-1";
    const proofHash = "bafybeigdyrztp4exampleproof";
    const expiresAt = (await ethers.provider.getBlock("latest")).timestamp + 3600;

    await expect(
      permissionReceipt
        .connect(granter)
        .mint(granter.address, grantee.address, scope, tokenURI, proofHash, expiresAt)
    )
      .to.emit(permissionReceipt, "ReceiptMinted")
      .withArgs(1, granter.address, grantee.address, scope, tokenURI, proofHash, expiresAt);

    expect(await permissionReceipt.ownerOf(1)).to.equal(grantee.address);

    const receipt = await permissionReceipt.receipts(1);
    expect(receipt.granter).to.equal(granter.address);
    expect(receipt.grantee).to.equal(grantee.address);
    expect(receipt.scope).to.equal(scope);
    expect(receipt.proofHash).to.equal(proofHash);
    expect(receipt.expiresAt).to.equal(expiresAt);
    expect(receipt.active).to.equal(true);
    expect(receipt.revokedAt).to.equal(0n);
  });

  it("reverts mint when caller is not the declared granter", async function () {
    const { permissionReceipt, granter, grantee, other } = await deployFixture();

    await expect(
      permissionReceipt
        .connect(other)
        .mint(granter.address, grantee.address, "scope", "ipfs://x", "proof", 0)
    ).to.be.revertedWithCustomError(permissionReceipt, "InvalidGranterCaller");
  });

  it("allows only the granter to revoke and burns the token", async function () {
    const { permissionReceipt, granter, grantee, other } = await deployFixture();

    await permissionReceipt
      .connect(granter)
      .mint(granter.address, grantee.address, "write:reports", "ipfs://permission-receipt-2", "proof", 0);

    await expect(permissionReceipt.connect(other).revoke(1)).to.be.revertedWithCustomError(
      permissionReceipt,
      "NotGranter"
    );

    await expect(permissionReceipt.connect(granter).revoke(1)).to.emit(
      permissionReceipt,
      "ReceiptRevoked"
    );

    await expect(permissionReceipt.ownerOf(1)).to.be.revertedWithCustomError(
      permissionReceipt,
      "ERC721NonexistentToken"
    );

    const receipt = await permissionReceipt.receipts(1);
    expect(receipt.active).to.equal(false);
    expect(receipt.revokedAt).to.not.equal(0n);
  });

  it("reverts in getPermission when receipt is expired", async function () {
    const { permissionReceipt, granter, grantee } = await deployFixture();

    const now = (await ethers.provider.getBlock("latest")).timestamp;
    const expiresAt = now + 60;

    await permissionReceipt
      .connect(granter)
      .mint(granter.address, grantee.address, "session", "ipfs://permission-receipt-3", "proof", expiresAt);

    await ethers.provider.send("evm_increaseTime", [61]);
    await ethers.provider.send("evm_mine");

    await expect(permissionReceipt.getPermission(1)).to.be.revertedWithCustomError(
      permissionReceipt,
      "PermissionExpired"
    );
  });

  it("reverts transfers because token is soulbound", async function () {
    const { permissionReceipt, granter, grantee, other } = await deployFixture();

    await permissionReceipt
      .connect(granter)
      .mint(granter.address, grantee.address, "admin", "ipfs://permission-receipt-4", "proof", 0);

    await expect(
      permissionReceipt.connect(grantee).transferFrom(grantee.address, other.address, 1)
    ).to.be.revertedWithCustomError(permissionReceipt, "Soulbound");
  });
});
