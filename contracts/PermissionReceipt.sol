// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC721URIStorage} from "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";

contract PermissionReceipt is ERC721URIStorage {
    error NotGranter();
    error Soulbound();
    error InvalidGranterCaller();
    error AlreadyRevoked();
    error NotRevoked();
    error ReceiptNotFound();

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
    mapping(uint256 => mapping(bytes32 => bool)) private _hasScopeHash;

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
        return keccak256(bytes(scope));
    }

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

        tokenId = _nextTokenId++;

        _safeMint(grantee, tokenId);
        _setTokenURI(tokenId, metadataURI);

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

        uint256 count = scopeHashes.length;
        for (uint256 i = 0; i < count; i++) {
            bytes32 hash = scopeHashes[i];
            if (!_hasScopeHash[tokenId][hash]) {
                _hasScopeHash[tokenId][hash] = true;
                _scopeHashesByToken[tokenId].push(hash);
            }
        }

        emit ReceiptMinted(tokenId, granter, grantee, _scopeHashesByToken[tokenId], expiresAt, proofHash);
    }

    function scopeHashesOf(uint256 tokenId) external view returns (bytes32[] memory) {
        _requireReceipt(tokenId);
        return _scopeHashesByToken[tokenId];
    }

    function hasScopeHash(uint256 tokenId, bytes32 hash) public view returns (bool) {
        if (!receipts[tokenId].exists) {
            return false;
        }
        return _hasScopeHash[tokenId][hash];
    }

    function hasScope(uint256 tokenId, string calldata scope) external view returns (bool) {
        return hasScopeHash(tokenId, scopeHash(scope));
    }

    function revoke(uint256 tokenId) external {
        _requireReceipt(tokenId);

        Receipt storage receipt = receipts[tokenId];
        if (receipt.granter != msg.sender) {
            revert NotGranter();
        }
        if (!receipt.active) {
            revert AlreadyRevoked();
        }

        receipt.active = false;
        receipt.revokedAt = uint64(block.timestamp);

        emit ReceiptRevoked(tokenId, receipt.revokedAt);
    }

    function burnRevoked(uint256 tokenId) external {
        _requireReceipt(tokenId);

        Receipt storage receipt = receipts[tokenId];
        if (receipt.granter != msg.sender) {
            revert NotGranter();
        }
        if (receipt.active || receipt.revokedAt == 0) {
            revert NotRevoked();
        }

        _burn(tokenId);
    }

    function isExpired(uint256 tokenId, uint64 timestamp) public view returns (bool) {
        _requireReceipt(tokenId);

        uint64 expiry = receipts[tokenId].expiresAt;
        return expiry != 0 && timestamp > expiry;
    }

    function isRevoked(uint256 tokenId) public view returns (bool) {
        _requireReceipt(tokenId);

        return !receipts[tokenId].active;
    }

    function isValid(uint256 tokenId, bytes32 requiredScopeHash, uint64 timestamp) external view returns (bool) {
        Receipt storage receipt = receipts[tokenId];

        if (!receipt.exists) {
            return false;
        }
        if (!receipt.active) {
            return false;
        }
        if (receipt.expiresAt != 0 && timestamp > receipt.expiresAt) {
            return false;
        }
        if (requiredScopeHash != bytes32(0) && !_hasScopeHash[tokenId][requiredScopeHash]) {
            return false;
        }

        return true;
    }

    function _requireReceipt(uint256 tokenId) internal view {
        if (!receipts[tokenId].exists) {
            revert ReceiptNotFound();
        }
    }

    function _update(address to, uint256 tokenId, address auth) internal override returns (address) {
        address from = _ownerOf(tokenId);

        if (from != address(0) && to != address(0)) {
            revert Soulbound();
        }

        return super._update(to, tokenId, auth);
    }
}
