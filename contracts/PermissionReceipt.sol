// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {ERC721URIStorage} from "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";

contract PermissionReceipt is ERC721URIStorage, EIP712 {
    string public constant SCOPE_HASH_DOMAIN_PREFIX = "PERMCHAIN_SCOPE_V1:";

    error NotGranter();
    error Soulbound();
    error NonexistentReceipt();
    error ZeroAddressGrantee();
    error EmptyScopes();
    error InvalidSignature();
    error SignatureDeadlineExpired();

    bytes32 private constant MINT_WITH_SIG_TYPEHASH =
        keccak256(
            "MintWithSig(address granter,address grantee,bytes32 scopeHashesHash,bytes32 metadataURIHash,bytes32 proofHash,uint64 expiresAt,uint256 nonce,uint256 deadline)"
        );

    struct Receipt {
        address granter;
        address grantee;
        bytes32 proofHash;
        uint64 issuedAt;
        uint64 expiresAt;
        uint64 revokedAt;
        bool active;
        bool exists;
    }

    struct MintWithSigRequest {
        address grantee;
        bytes32[] scopeHashes;
        string metadataURI;
        bytes32 proofHash;
        uint64 expiresAt;
        uint256 deadline;
    }

    uint256 private _nextTokenId = 1;

    mapping(uint256 => Receipt) public receipts;
    mapping(address => uint256) public nonces;
    mapping(uint256 => bytes32[]) private _scopeHashesByToken;
    mapping(uint256 => mapping(bytes32 => bool)) private _scopeHashExists;

    event ReceiptMinted(
        uint256 indexed tokenId,
        address indexed granter,
        address indexed grantee,
        bytes32[] scopeHashes,
        uint64 expiresAt,
        bytes32 proofHash
    );

    event ReceiptRevoked(uint256 indexed tokenId, uint64 indexed revokedAt);

    constructor() ERC721("PermissionReceipt", "PRCPT") EIP712("PermissionReceipt", "1") {}

    function scopeHash(string calldata scope) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(SCOPE_HASH_DOMAIN_PREFIX, scope));
    }

    function mint(
        address grantee,
        bytes32[] calldata scopeHashes,
        string calldata metadataURI,
        bytes32 proofHash,
        uint64 expiresAt
    ) external returns (uint256 tokenId) {
        tokenId = _mintReceipt(msg.sender, grantee, scopeHashes, metadataURI, proofHash, expiresAt);
    }

    function mintWithSig(
        address granter,
        MintWithSigRequest calldata request,
        bytes calldata signature
    ) external returns (uint256 tokenId) {
        if (block.timestamp > request.deadline) {
            revert SignatureDeadlineExpired();
        }

        uint256 nonce = nonces[granter];

        if (ECDSA.recover(_hashMintWithSig(granter, request, nonce), signature) != granter) {
            revert InvalidSignature();
        }

        unchecked {
            nonces[granter] = nonce + 1;
        }

        tokenId = _mintReceipt(
            granter,
            request.grantee,
            request.scopeHashes,
            request.metadataURI,
            request.proofHash,
            request.expiresAt
        );
    }

    function _hashMintWithSig(
        address granter,
        MintWithSigRequest calldata request,
        uint256 nonce
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                MINT_WITH_SIG_TYPEHASH,
                granter,
                request.grantee,
                keccak256(abi.encode(request.scopeHashes)),
                keccak256(bytes(request.metadataURI)),
                request.proofHash,
                request.expiresAt,
                nonce,
                request.deadline
            )
        );

        return _hashTypedDataV4(structHash);
    }

    function _mintReceipt(
        address granter,
        address grantee,
        bytes32[] calldata scopeHashes,
        string calldata metadataURI,
        bytes32 proofHash,
        uint64 expiresAt
    ) internal returns (uint256 tokenId) {
        if (grantee == address(0)) {
            revert ZeroAddressGrantee();
        }

        if (scopeHashes.length == 0) {
            revert EmptyScopes();
        }

        tokenId = _nextTokenId++;

        _safeMint(grantee, tokenId);
        _setTokenURI(tokenId, metadataURI);

        uint256 scopeCount = scopeHashes.length;
        for (uint256 i = 0; i < scopeCount; i++) {
            bytes32 currentScopeHash = scopeHashes[i];

            if (!_scopeHashExists[tokenId][currentScopeHash]) {
                _scopeHashExists[tokenId][currentScopeHash] = true;
                _scopeHashesByToken[tokenId].push(currentScopeHash);
            }
        }

        receipts[tokenId] = Receipt({
            granter: granter,
            grantee: grantee,
            proofHash: proofHash,
            issuedAt: uint64(block.timestamp),
            expiresAt: expiresAt,
            revokedAt: 0,
            active: true,
            exists: true
        });

        emit ReceiptMinted(
            tokenId,
            granter,
            grantee,
            _scopeHashesByToken[tokenId],
            expiresAt,
            proofHash
        );
    }

    function getScopeHashes(uint256 tokenId) external view returns (bytes32[] memory) {
        if (!exists(tokenId)) {
            revert NonexistentReceipt();
        }

        return _scopeHashesByToken[tokenId];
    }

    function hasScopeHash(uint256 tokenId, bytes32 requiredScopeHash) public view returns (bool) {
        if (!exists(tokenId)) {
            return false;
        }

        return _scopeHashExists[tokenId][requiredScopeHash];
    }

    function hasScope(uint256 tokenId, string calldata scope) external view returns (bool) {
        return hasScopeHash(tokenId, scopeHash(scope));
    }

    function exists(uint256 tokenId) public view returns (bool) {
        return _ownerOf(tokenId) != address(0);
    }

    function revoke(uint256 tokenId) external {
        if (!exists(tokenId)) {
            revert NonexistentReceipt();
        }

        Receipt storage receipt = receipts[tokenId];

        if (receipt.granter != msg.sender) {
            revert NotGranter();
        }

        if (!receipt.active) {
            return;
        }

        receipt.active = false;
        receipt.revokedAt = uint64(block.timestamp);

        emit ReceiptRevoked(tokenId, receipt.revokedAt);
    }

    function getPermission(uint256 tokenId) external view returns (Receipt memory receipt) {
        if (!exists(tokenId)) {
            revert NonexistentReceipt();
        }

        receipt = receipts[tokenId];
    }

    function isExpired(uint256 tokenId, uint64 timestamp) public view returns (bool) {
        if (!exists(tokenId)) {
            return false;
        }

        Receipt memory receipt = receipts[tokenId];
        return receipt.expiresAt != 0 && timestamp > receipt.expiresAt;
    }

    function isRevoked(uint256 tokenId) public view returns (bool) {
        if (!exists(tokenId)) {
            return false;
        }

        return !receipts[tokenId].active;
    }

    function isValid(uint256 tokenId, bytes32 requiredScopeHash, uint64 timestamp) public view returns (bool) {
        if (!exists(tokenId)) {
            return false;
        }

        if (isRevoked(tokenId)) {
            return false;
        }

        if (isExpired(tokenId, timestamp)) {
            return false;
        }

        if (requiredScopeHash != bytes32(0) && !hasScopeHash(tokenId, requiredScopeHash)) {
            return false;
        }

        return true;
    }

    function _update(address to, uint256 tokenId, address auth) internal override returns (address) {
        address from = _ownerOf(tokenId);

        if (from != address(0) && to != address(0)) {
            revert Soulbound();
        }

        return super._update(to, tokenId, auth);
    }
}
