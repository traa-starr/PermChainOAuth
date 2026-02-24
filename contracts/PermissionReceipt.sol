// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC721URIStorage} from "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";

contract PermissionReceipt is ERC721URIStorage {
    string public constant SCOPE_HASH_DOMAIN = "PERMCHAIN_SCOPE_V1:";
    error NotGranter();
    error Soulbound();
    error InvalidGranterCaller();
    error NonexistentReceipt();
    error ZeroAddressGrantee();
    error EmptyScopes();

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

    uint256 private _nextTokenId = 1;

    mapping(uint256 => Receipt) public receipts;
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

    constructor() ERC721("PermissionReceipt", "PRCPT") {}

    function scopeHash(string calldata scope) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(SCOPE_HASH_DOMAIN, scope));
    }

    /// @notice Mints a non-transferable permission receipt with hashed scopes.
    /// @dev Expired-at-mint receipts are allowed by policy; use `isValid` for authorization truth.
    function mint(
        address granter,
        address grantee,
        bytes32[] calldata scopeHashes,
        string calldata metadataURI,
        bytes32 proofHash,
        uint64 expiresAt
    ) external returns (uint256 tokenId) {
        if (granter != msg.sender) {
            revert InvalidGranterCaller();
        }

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

    /// @notice Returns the scope hashes stored for a receipt.
    function getScopeHashes(uint256 tokenId) external view returns (bytes32[] memory) {
        if (!exists(tokenId)) {
            revert NonexistentReceipt();
        }

        return _scopeHashesByToken[tokenId];
    }

    /// @notice Returns whether a receipt includes a required scope hash.
    /// @dev Returns false for nonexistent receipts to avoid ambiguous mapping reads.
    function hasScopeHash(uint256 tokenId, bytes32 requiredScopeHash) public view returns (bool) {
        if (!exists(tokenId)) {
            return false;
        }

        return _scopeHashExists[tokenId][requiredScopeHash];
    }

    function hasScope(uint256 tokenId, string calldata scope) external view returns (bool) {
        return hasScopeHash(tokenId, scopeHash(scope));
    }

    /// @notice Returns true when the receipt NFT exists.
    /// @dev Existence is defined by ERC721 ownership state (`_ownerOf(tokenId) != address(0)`).
    function exists(uint256 tokenId) public view returns (bool) {
        return _ownerOf(tokenId) != address(0);
    }

    /// @notice Revokes a receipt without burning it, preserving historical queryability.
    /// @dev Reverts for nonexistent receipts; returns early if already revoked.
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

    /// @notice Returns whether a receipt is expired at `timestamp`.
    /// @dev Returns false for nonexistent receipts. Expiry is only enforced when `expiresAt != 0`.
    function isExpired(uint256 tokenId, uint64 timestamp) public view returns (bool) {
        if (!exists(tokenId)) {
            return false;
        }

        Receipt memory receipt = receipts[tokenId];
        return receipt.expiresAt != 0 && timestamp > receipt.expiresAt;
    }

    /// @notice Returns whether a receipt has been revoked.
    /// @dev Returns false for nonexistent receipts.
    function isRevoked(uint256 tokenId) public view returns (bool) {
        if (!exists(tokenId)) {
            return false;
        }

        return !receipts[tokenId].active;
    }

    /// @notice Canonical authorization truth helper for integrators.
    /// @dev Returns false unless the token exists, is not revoked, is not expired at `timestamp`,
    /// and contains `requiredScopeHash` when it is non-zero.
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
