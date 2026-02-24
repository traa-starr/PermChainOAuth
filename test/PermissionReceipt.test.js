const { anyValue } = require("@nomicfoundation/hardhat-chai-matchers/withArgs");
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

  function hashScope(scope) {
    return ethers.keccak256(ethers.toUtf8Bytes(scope));
  }

  it("mints with multiple scopes and supports hasScopeHash/hasScope", async function () {
    const { permissionReceipt, granter, grantee } = await deployFixture();

    const scopes = [hashScope("read:reports"), hashScope("write:reports")];
    const tokenURI = "ipfs://permission-receipt-1";
    const proofHash = ethers.keccak256(ethers.toUtf8Bytes("proof-1"));
    const expiresAt = BigInt((await ethers.provider.getBlock("latest")).timestamp + 3600);

    await expect(
      permissionReceipt
        .connect(granter)
        .mint(granter.address, grantee.address, scopes, tokenURI, proofHash, expiresAt)
    )
      .to.emit(permissionReceipt, "ReceiptMinted")
      .withArgs(1, granter.address, grantee.address, scopes, expiresAt, proofHash);

    expect(await permissionReceipt.ownerOf(1)).to.equal(grantee.address);
    expect(await permissionReceipt.hasScopeHash(1, scopes[0])).to.equal(true);
    expect(await permissionReceipt.hasScopeHash(1, scopes[1])).to.equal(true);
    expect(await permissionReceipt.hasScope(1, "read:reports")).to.equal(true);

    const receipt = await permissionReceipt.receipts(1);
    expect(receipt.granter).to.equal(granter.address);
    expect(receipt.grantee).to.equal(grantee.address);
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
        .mint(granter.address, grantee.address, [hashScope("scope")], "ipfs://x", ethers.ZeroHash, 0)
    ).to.be.revertedWithCustomError(permissionReceipt, "InvalidGranterCaller");
  });

  it("keeps revoked receipts queryable and invalid", async function () {
    const { permissionReceipt, granter, grantee, other } = await deployFixture();
    const scope = hashScope("write:reports");

    await permissionReceipt
      .connect(granter)
      .mint(granter.address, grantee.address, [scope], "ipfs://permission-receipt-2", ethers.ZeroHash, 0);

    await expect(permissionReceipt.connect(other).revoke(1)).to.be.revertedWithCustomError(
      permissionReceipt,
      "NotGranter"
    );

    await expect(permissionReceipt.connect(granter).revoke(1))
      .to.emit(permissionReceipt, "ReceiptRevoked")
      .withArgs(1, anyValue);

    expect(await permissionReceipt.ownerOf(1)).to.equal(grantee.address);
    expect(await permissionReceipt.isRevoked(1)).to.equal(true);

    const receipt = await permissionReceipt.receipts(1);
    expect(receipt.active).to.equal(false);
    expect(receipt.revokedAt).to.not.equal(0n);

    const now = BigInt((await ethers.provider.getBlock("latest")).timestamp);
    expect(await permissionReceipt.isValid(1, scope, now)).to.equal(false);
  });

  it("isValid returns false immediately when expiresAt is in the past", async function () {
    const { permissionReceipt, granter, grantee } = await deployFixture();
    const now = (await ethers.provider.getBlock("latest")).timestamp;
    const scope = hashScope("session");

    await permissionReceipt
      .connect(granter)
      .mint(granter.address, grantee.address, [scope], "ipfs://permission-receipt-3", ethers.ZeroHash, now - 1);

    expect(await permissionReceipt.isValid(1, scope, now)).to.equal(false);
    expect(await permissionReceipt.isExpired(1, now)).to.equal(true);
  });

  it("reverts transfers because token is soulbound", async function () {
    const { permissionReceipt, granter, grantee, other } = await deployFixture();

    await permissionReceipt
      .connect(granter)
      .mint(granter.address, grantee.address, [hashScope("admin")], "ipfs://permission-receipt-4", ethers.ZeroHash, 0);

    await expect(
      permissionReceipt.connect(grantee).transferFrom(grantee.address, other.address, 1)
    ).to.be.revertedWithCustomError(permissionReceipt, "Soulbound");
  });

  it("returns false for scope mismatch and true when requiredScopeHash is zero", async function () {
    const { permissionReceipt, granter, grantee } = await deployFixture();

    const mintedScope = hashScope("read:payments");
    const requiredScope = hashScope("write:payments");

    await permissionReceipt
      .connect(granter)
      .mint(granter.address, grantee.address, [mintedScope], "ipfs://permission-receipt-5", ethers.ZeroHash, 0);

    const now = BigInt((await ethers.provider.getBlock("latest")).timestamp);
    expect(await permissionReceipt.isValid(1, requiredScope, now)).to.equal(false);
    expect(await permissionReceipt.isValid(1, ethers.ZeroHash, now)).to.equal(true);
  });

  it("supports timestamp-based validation", async function () {
    const { permissionReceipt, granter, grantee } = await deployFixture();

    const now = (await ethers.provider.getBlock("latest")).timestamp;
    const expiresAt = now + 120;
    const scope = hashScope("read:invoices");

    await permissionReceipt
      .connect(granter)
      .mint(granter.address, grantee.address, [scope], "ipfs://permission-receipt-6", ethers.ZeroHash, expiresAt);

    expect(await permissionReceipt.isValid(1, scope, now + 60)).to.equal(true);
    expect(await permissionReceipt.isValid(1, scope, expiresAt + 1)).to.equal(false);
  });
});
