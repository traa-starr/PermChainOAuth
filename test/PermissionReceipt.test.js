const { anyValue } = require("@nomicfoundation/hardhat-chai-matchers/withArgs");
const { expect } = require("chai");
const { ethers } = require("hardhat");
const { hashScope: offchainHashScope } = require("../server");

describe("PermissionReceipt", function () {
  async function deployFixture() {
    const [granter, grantee, other] = await ethers.getSigners();
    const PermissionReceipt = await ethers.getContractFactory(
      "PermissionReceipt"
    );
    const permissionReceipt = await PermissionReceipt.deploy();
    await permissionReceipt.waitForDeployment();

    return { permissionReceipt, granter, grantee, other };
  }

  function hashScope(scope) {
    return ethers.keccak256(
      ethers.toUtf8Bytes(`PERMCHAIN_SCOPE_V1:${scope}`)
    );
  }

  it("matches on-chain and off-chain scope hashing", async function () {
    const { permissionReceipt } = await deployFixture();

    const scope = "ai:train_data";
    const onchainHash = await permissionReceipt.scopeHash(scope);
    const offchainHash = offchainHashScope(scope);

    expect(onchainHash).to.equal(offchainHash);
  });

  function hashProof(granter, primaryScopeHash, nonce, expiresAt) {
    return ethers.keccak256(
      ethers.solidityPacked(
        ["address", "bytes32", "bytes32", "uint64"],
        [granter, primaryScopeHash, nonce, expiresAt]
      )
    );
  }

  it("mints with multiple scopes and exposes them via hasScopeHash", async function () {
    const { permissionReceipt, granter, grantee } = await deployFixture();

    const scopes = ["read:reports", "write:reports", "read:calendar"];
    const scopeHashes = scopes.map(hashScope);
    const expiresAt = BigInt(
      (await ethers.provider.getBlock("latest")).timestamp + 3600
    );
    const proofHash = hashProof(
      granter.address,
      scopeHashes[0],
      ethers.id("nonce-1"),
      expiresAt
    );

    await expect(
      permissionReceipt
        .connect(granter)
        .mint(
          grantee.address,
          scopeHashes,
          "ipfs://permission-receipt-1",
          proofHash,
          expiresAt
        )
    )
      .to.emit(permissionReceipt, "ReceiptMinted")
      .withArgs(
        1,
        granter.address,
        grantee.address,
        scopeHashes,
        expiresAt,
        proofHash
      );

    expect(await permissionReceipt.hasScopeHash(1, scopeHashes[0])).to.equal(
      true
    );
    expect(await permissionReceipt.hasScopeHash(1, scopeHashes[1])).to.equal(
      true
    );
    expect(await permissionReceipt.hasScopeHash(1, scopeHashes[2])).to.equal(
      true
    );
    expect(
      await permissionReceipt.hasScopeHash(1, hashScope("delete:reports"))
    ).to.equal(false);

    const onChainScopeHashes = await permissionReceipt.getScopeHashes(1);
    expect(onChainScopeHashes).to.deep.equal(scopeHashes);
  });

  it("reverts mint with zero-address grantee", async function () {
    const { permissionReceipt, granter } = await deployFixture();

    await expect(
      permissionReceipt
        .connect(granter)
        .mint(
          ethers.ZeroAddress,
          [hashScope("scope")],
          "ipfs://x",
          ethers.id("proof"),
          0
        )
    ).to.be.revertedWithCustomError(permissionReceipt, "ZeroAddressGrantee");
  });

  it("reverts mint with empty scopes", async function () {
    const { permissionReceipt, granter, grantee } = await deployFixture();

    await expect(
      permissionReceipt
        .connect(granter)
        .mint(
          grantee.address,
          [],
          "ipfs://x",
          ethers.id("proof"),
          0
        )
    ).to.be.revertedWithCustomError(permissionReceipt, "EmptyScopes");
  });

  it("isValid is immediately false for receipts minted with past expiry", async function () {
    const { permissionReceipt, granter, grantee } = await deployFixture();

    const now = (await ethers.provider.getBlock("latest")).timestamp;
    const expiresAt = BigInt(now - 1);
    const scope = hashScope("session");

    await expect(
      permissionReceipt
        .connect(granter)
        .mint(
          grantee.address,
          [scope],
          "ipfs://permission-receipt-2",
          ethers.id("proof"),
          expiresAt
        )
    ).to.not.be.reverted;

    expect(await permissionReceipt.isExpired(1, BigInt(now))).to.equal(true);
    expect(await permissionReceipt.isValid(1, scope, BigInt(now))).to.equal(
      false
    );
  });

  it("revoke marks receipt revoked and makes isValid false without burning", async function () {
    const { permissionReceipt, granter, grantee } = await deployFixture();

    const scope = hashScope("admin");

    await permissionReceipt
      .connect(granter)
      .mint(
        grantee.address,
        [scope],
        "ipfs://permission-receipt-3",
        ethers.id("proof"),
        0
      );

    await expect(permissionReceipt.connect(granter).revoke(1))
      .to.emit(permissionReceipt, "ReceiptRevoked")
      .withArgs(1, anyValue);

    expect(await permissionReceipt.ownerOf(1)).to.equal(grantee.address);
    expect(await permissionReceipt.isRevoked(1)).to.equal(true);
    expect(
      await permissionReceipt.isValid(
        1,
        scope,
        BigInt((await ethers.provider.getBlock("latest")).timestamp)
      )
    ).to.equal(false);

    const receipt = await permissionReceipt.receipts(1);
    expect(receipt.active).to.equal(false);
    expect(receipt.revokedAt).to.not.equal(0n);

    const now = BigInt((await ethers.provider.getBlock("latest")).timestamp);
    expect(await permissionReceipt.isValid(1, scope, now)).to.equal(false);
  });

  it("revoke reverts for nonexistent receipt", async function () {
    const { permissionReceipt, granter } = await deployFixture();

    await expect(
      permissionReceipt.connect(granter).revoke(123)
    ).to.be.revertedWithCustomError(permissionReceipt, "NonexistentReceipt");
  });

  it("keeps revoke idempotent", async function () {
    const { permissionReceipt, granter, grantee } = await deployFixture();

    await permissionReceipt
      .connect(granter)
      .mint(
        grantee.address,
        [hashScope("read:reports")],
        "ipfs://permission-receipt-4",
        ethers.id("proof"),
        0
      );

    await permissionReceipt.connect(granter).revoke(1);
    await expect(permissionReceipt.connect(granter).revoke(1)).to.not.be
      .reverted;
  });

  it("enforces soulbound non-transferability", async function () {
    const { permissionReceipt, granter, grantee, other } =
      await deployFixture();

    await permissionReceipt
      .connect(granter)
      .mint(
        grantee.address,
        [hashScope("read:reports")],
        "ipfs://permission-receipt-5",
        ethers.id("proof"),
        0
      );

    await expect(
      permissionReceipt
        .connect(grantee)
        .transferFrom(grantee.address, other.address, 1)
    ).to.be.revertedWithCustomError(permissionReceipt, "Soulbound");
  });

  it("returns false for scope mismatch", async function () {
    const { permissionReceipt, granter, grantee } = await deployFixture();

    const readScope = hashScope("read:reports");
    const writeScope = hashScope("write:reports");

    await permissionReceipt
      .connect(granter)
      .mint(
        grantee.address,
        [readScope],
        "ipfs://permission-receipt-6",
        ethers.id("proof"),
        0
      );

    const now = BigInt((await ethers.provider.getBlock("latest")).timestamp);

    expect(await permissionReceipt.isValid(1, writeScope, now)).to.equal(false);
    expect(await permissionReceipt.hasScope(1, "read:reports")).to.equal(true);
    expect(await permissionReceipt.hasScope(1, "write:reports")).to.equal(
      false
    );
  });

  it("supports timestamp-based validation with custom timestamp param", async function () {
    const { permissionReceipt, granter, grantee } = await deployFixture();

    const now = (await ethers.provider.getBlock("latest")).timestamp;
    const expiresAt = BigInt(now + 120);
    const scope = hashScope("session");

    await permissionReceipt
      .connect(granter)
      .mint(
        grantee.address,
        [scope],
        "ipfs://permission-receipt-7",
        ethers.id("proof"),
        expiresAt
      );

    expect(
      await permissionReceipt.isValid(1, scope, BigInt(now + 100))
    ).to.equal(true);
    expect(
      await permissionReceipt.isValid(1, scope, BigInt(now + 121))
    ).to.equal(false);

    expect(
      await permissionReceipt.isValid(1, ethers.ZeroHash, BigInt(now + 100))
    ).to.equal(true);
  });

  it("returns consistent helper behavior for nonexistent receipts", async function () {
    const { permissionReceipt } = await deployFixture();

    expect(await permissionReceipt.exists(999)).to.equal(false);
    expect(await permissionReceipt.isRevoked(999)).to.equal(false);
    expect(await permissionReceipt.isExpired(999, 123)).to.equal(false);
    expect(
      await permissionReceipt.hasScopeHash(999, hashScope("read:reports"))
    ).to.equal(false);
    expect(await permissionReceipt.isValid(999, ethers.ZeroHash, 0)).to.equal(
      false
    );
  });

  it("getPermission reverts for nonexistent receipt", async function () {
    const { permissionReceipt } = await deployFixture();

    await expect(
      permissionReceipt.getPermission(42)
    ).to.be.revertedWithCustomError(permissionReceipt, "NonexistentReceipt");
  });

  it("getScopeHashes reverts for nonexistent receipt", async function () {
    const { permissionReceipt } = await deployFixture();

    await expect(
      permissionReceipt.getScopeHashes(42)
    ).to.be.revertedWithCustomError(permissionReceipt, "NonexistentReceipt");
  });

});



  async function signMintWithSig(
    permissionReceipt,
    granter,
    payload
  ) {
    const chainId = (await ethers.provider.getNetwork()).chainId;
    const nonce = await permissionReceipt.nonces(granter.address);

    const domain = {
      name: "PermissionReceipt",
      version: "1",
      chainId,
      verifyingContract: await permissionReceipt.getAddress(),
    };

    const types = {
      MintWithSig: [
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

    const message = {
      granter: granter.address,
      grantee: payload.grantee,
      scopeHashesHash: ethers.keccak256(
        ethers.solidityPacked(
          Array(payload.scopeHashes.length).fill("bytes32"),
          payload.scopeHashes
        )
      ),
      metadataURIHash: ethers.keccak256(ethers.toUtf8Bytes(payload.metadataURI)),
      proofHash: payload.proofHash,
      expiresAt: payload.expiresAt,
      nonce,
      deadline: payload.deadline,
    };

    return granter.signTypedData(domain, types, message);
  }

  it("mints with a valid EIP-712 signature", async function () {
    const { permissionReceipt, granter, grantee, other } = await deployFixture();

    const payload = {
      grantee: grantee.address,
      scopeHashes: [hashScope("read:reports"), hashScope("write:reports")],
      metadataURI: "ipfs://permission-receipt-sig-1",
      proofHash: ethers.id("sig-proof-1"),
      expiresAt: 0,
      deadline: BigInt((await ethers.provider.getBlock("latest")).timestamp + 3600),
    };

    const signature = await signMintWithSig(permissionReceipt, granter, payload);

    await expect(
      permissionReceipt.connect(other).mintWithSig(
        granter.address,
        payload,
        signature
      )
    )
      .to.emit(permissionReceipt, "ReceiptMinted")
      .withArgs(1, granter.address, payload.grantee, payload.scopeHashes, payload.expiresAt, payload.proofHash);

    const receipt = await permissionReceipt.receipts(1);
    expect(receipt.granter).to.equal(granter.address);
    expect(await permissionReceipt.nonces(granter.address)).to.equal(1n);
  });

  it("rejects replayed signatures via nonce protection", async function () {
    const { permissionReceipt, granter, grantee, other } = await deployFixture();

    const payload = {
      grantee: grantee.address,
      scopeHashes: [hashScope("read:reports")],
      metadataURI: "ipfs://permission-receipt-sig-2",
      proofHash: ethers.id("sig-proof-2"),
      expiresAt: 0,
      deadline: BigInt((await ethers.provider.getBlock("latest")).timestamp + 3600),
    };

    const signature = await signMintWithSig(permissionReceipt, granter, payload);

    await permissionReceipt.connect(other).mintWithSig(
      granter.address,
      payload,
      signature
    );

    await expect(
      permissionReceipt.connect(other).mintWithSig(
        granter.address,
        payload,
        signature
      )
    ).to.be.revertedWithCustomError(permissionReceipt, "InvalidSignature");
  });

  it("rejects mintWithSig when deadline is expired", async function () {
    const { permissionReceipt, granter, grantee, other } = await deployFixture();

    const payload = {
      grantee: grantee.address,
      scopeHashes: [hashScope("read:reports")],
      metadataURI: "ipfs://permission-receipt-sig-3",
      proofHash: ethers.id("sig-proof-3"),
      expiresAt: 0,
      deadline: BigInt((await ethers.provider.getBlock("latest")).timestamp - 1),
    };

    const signature = await signMintWithSig(permissionReceipt, granter, payload);

    await expect(
      permissionReceipt.connect(other).mintWithSig(
        granter.address,
        payload,
        signature
      )
    ).to.be.revertedWithCustomError(permissionReceipt, "SignatureDeadlineExpired");
  });

  it("enforces signed scopes by rejecting tampered scope payloads", async function () {
    const { permissionReceipt, granter, grantee, other } = await deployFixture();

    const payload = {
      grantee: grantee.address,
      scopeHashes: [hashScope("read:reports")],
      metadataURI: "ipfs://permission-receipt-sig-4",
      proofHash: ethers.id("sig-proof-4"),
      expiresAt: 0,
      deadline: BigInt((await ethers.provider.getBlock("latest")).timestamp + 3600),
    };

    const signature = await signMintWithSig(permissionReceipt, granter, payload);

    await expect(
      permissionReceipt.connect(other).mintWithSig(
        granter.address,
        {
          ...payload,
          scopeHashes: [payload.scopeHashes[0], hashScope("write:reports")],
        },
        signature
      )
    ).to.be.revertedWithCustomError(permissionReceipt, "InvalidSignature");
  });

});

