const { anyValue } = require("@nomicfoundation/hardhat-chai-matchers/withArgs");
const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("PermissionReceipt", function () {
  async function deployFixture() {
    const [granter, grantee, relayer, other] = await ethers.getSigners();
    const PermissionReceipt = await ethers.getContractFactory("PermissionReceipt");
    const permissionReceipt = await PermissionReceipt.deploy();
    await permissionReceipt.waitForDeployment();

    return { permissionReceipt, granter, grantee, relayer, other };
  }

  function hashScope(scope) {
    return ethers.keccak256(ethers.toUtf8Bytes(`PERMCHAIN_SCOPE_V1:${scope}`));
  }

  function hashProof(granter, primaryScopeHash, nonce, expiresAt) {
    return ethers.keccak256(
      ethers.solidityPacked(
        ["address", "bytes32", "bytes32", "uint64"],
        [granter, primaryScopeHash, nonce, expiresAt]
      )
    );
  }

  async function signMintRequest(permissionReceipt, granter, payload) {
    const nonce = await permissionReceipt.nonces(granter.address);
    const chainId = (await ethers.provider.getNetwork()).chainId;

    const domain = {
      name: "PermissionReceipt",
      version: "1",
      chainId,
      verifyingContract: await permissionReceipt.getAddress(),
    };

    const types = {
      MintRequest: [
        { name: "granter", type: "address" },
        { name: "grantee", type: "address" },
        { name: "scopeHashesHash", type: "bytes32" },
        { name: "metadataURIHash", type: "bytes32" },
        { name: "proofHash", type: "bytes32" },
        { name: "expiresAt", type: "uint64" },
        { name: "nonce", type: "uint256" },
        { name: "deadline", type: "uint256" },
      ],
    };

    const value = {
      granter: granter.address,
      grantee: payload.grantee,
      scopeHashesHash: ethers.solidityPackedKeccak256(
        Array(payload.scopeHashes.length).fill("bytes32"),
        payload.scopeHashes
      ),
      metadataURIHash: ethers.keccak256(ethers.toUtf8Bytes(payload.metadataURI)),
      proofHash: payload.proofHash,
      expiresAt: payload.expiresAt,
      nonce,
      deadline: payload.deadline,
    };

    return granter.signTypedData(domain, types, value);
  }

  it("matches on-chain and off-chain manifest scope hashing", async function () {
    const { permissionReceipt } = await deployFixture();

    const scope = "ai:train_data:use";
    expect(await permissionReceipt.scopeHash(scope)).to.equal(hashScope(scope));
  });

  it("mints with multiple scopes and exposes them via hasScopeHash/getScopeHashes", async function () {
    const { permissionReceipt, granter, grantee } = await deployFixture();

    const scopes = ["timeline:post:read", "timeline:post:write", "ai:train_data:use"];
    const scopeHashes = scopes.map(hashScope);
    const expiresAt = BigInt((await ethers.provider.getBlock("latest")).timestamp + 3600);
    const proofHash = hashProof(granter.address, scopeHashes[0], ethers.id("nonce-1"), expiresAt);

    await expect(
      permissionReceipt
        .connect(granter)
        .mint(grantee.address, scopeHashes, "ipfs://permission-receipt-1", proofHash, expiresAt)
    )
      .to.emit(permissionReceipt, "ReceiptMinted")
      .withArgs(1, granter.address, grantee.address, scopeHashes, expiresAt, proofHash);

    expect(await permissionReceipt.hasScopeHash(1, scopeHashes[0])).to.equal(true);
    expect(await permissionReceipt.hasScopeHash(1, scopeHashes[1])).to.equal(true);
    expect(await permissionReceipt.hasScopeHash(1, hashScope("timeline:post:delete"))).to.equal(false);

    expect(await permissionReceipt.getScopeHashes(1)).to.deep.equal(scopeHashes);
  });

  it("returns false for isValid scope mismatch", async function () {
    const { permissionReceipt, granter, grantee } = await deployFixture();

    const readScope = hashScope("timeline:post:read");
    const writeScope = hashScope("timeline:post:write");
    await permissionReceipt.connect(granter).mint(grantee.address, [readScope], "ipfs://x", ethers.id("proof"), 0);

    const now = BigInt((await ethers.provider.getBlock("latest")).timestamp);
    expect(await permissionReceipt.isValid(1, writeScope, now)).to.equal(false);
    expect(await permissionReceipt.isValid(1, readScope, now)).to.equal(true);
  });

  it("supports expiry validation via custom timestamp", async function () {
    const { permissionReceipt, granter, grantee } = await deployFixture();

    const now = (await ethers.provider.getBlock("latest")).timestamp;
    const expiresAt = BigInt(now + 120);
    const scope = hashScope("uls:wallet.session:issue");
    await permissionReceipt
      .connect(granter)
      .mint(grantee.address, [scope], "ipfs://permission-receipt-expiry", ethers.id("proof"), expiresAt);

    expect(await permissionReceipt.isValid(1, scope, BigInt(now + 100))).to.equal(true);
    expect(await permissionReceipt.isValid(1, scope, BigInt(now + 121))).to.equal(false);
    expect(await permissionReceipt.isExpired(1, BigInt(now + 121))).to.equal(true);
  });

  it("revoke makes isValid false without burning and remains idempotent", async function () {
    const { permissionReceipt, granter, grantee } = await deployFixture();

    const scope = hashScope("ai:model.weights:read.public");
    await permissionReceipt
      .connect(granter)
      .mint(grantee.address, [scope], "ipfs://permission-receipt-revoke", ethers.id("proof"), 0);

    await expect(permissionReceipt.connect(granter).revoke(1))
      .to.emit(permissionReceipt, "ReceiptRevoked")
      .withArgs(1, anyValue);

    expect(await permissionReceipt.ownerOf(1)).to.equal(grantee.address);
    expect(await permissionReceipt.isValid(1, scope, BigInt((await ethers.provider.getBlock("latest")).timestamp))).to.equal(false);

    await expect(permissionReceipt.connect(granter).revoke(1)).to.not.be.reverted;
    expect(await permissionReceipt.isRevoked(1)).to.equal(true);
  });

  it("applies nonexistent receipt semantics consistently", async function () {
    const { permissionReceipt, granter } = await deployFixture();
    const tokenId = 777;

    expect(await permissionReceipt.exists(tokenId)).to.equal(false);
    expect(await permissionReceipt.hasScopeHash(tokenId, hashScope("timeline:post:read"))).to.equal(false);
    expect(await permissionReceipt.hasScope(tokenId, "timeline:post:read")).to.equal(false);
    expect(await permissionReceipt.isRevoked(tokenId)).to.equal(false);
    expect(await permissionReceipt.isExpired(tokenId, 123n)).to.equal(false);
    expect(await permissionReceipt.isValid(tokenId, ethers.ZeroHash, 123n)).to.equal(false);

    await expect(permissionReceipt.getScopeHashes(tokenId)).to.be.revertedWithCustomError(
      permissionReceipt,
      "NonexistentReceipt"
    );
    await expect(permissionReceipt.connect(granter).revoke(tokenId)).to.be.revertedWithCustomError(
      permissionReceipt,
      "NonexistentReceipt"
    );
  });

  it("mints with EIP-712 signature, stores granter correctly, and blocks replay", async function () {
    const { permissionReceipt, granter, grantee, relayer } = await deployFixture();

    const payload = {
      grantee: grantee.address,
      scopeHashes: [hashScope("timeline:post:read"), hashScope("ai:train_data:use")],
      metadataURI: "ipfs://permission-receipt-sig-1",
      proofHash: ethers.id("sig-proof-1"),
      expiresAt: 0,
      deadline: BigInt((await ethers.provider.getBlock("latest")).timestamp + 3600),
    };

    const signature = await signMintRequest(permissionReceipt, granter, payload);

    await expect(permissionReceipt.connect(relayer).mintWithSig(granter.address, payload, signature))
      .to.emit(permissionReceipt, "ReceiptMinted")
      .withArgs(1, granter.address, grantee.address, payload.scopeHashes, payload.expiresAt, payload.proofHash);

    expect(await permissionReceipt.ownerOf(1)).to.equal(grantee.address);
    expect((await permissionReceipt.receipts(1)).granter).to.equal(granter.address);
    expect(await permissionReceipt.nonces(granter.address)).to.equal(1n);

    await expect(
      permissionReceipt.connect(relayer).mintWithSig(granter.address, payload, signature)
    ).to.be.revertedWithCustomError(permissionReceipt, "InvalidSignature");
  });
});
