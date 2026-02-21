// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC721URIStorage} from "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";

contract PermissionReceipt is ERC721URIStorage {
    error NotGranter();
    error Soulbound();
    error InvalidGranterCaller();
    error InactivePermission();
    error PermissionExpired();

    struct Receipt {
        address granter;
        address grantee;
        string scope;
        string proofHash;
        uint256 issuedAt;
        uint256 expiresAt;
        uint256 revokedAt;
        bool active;
    }

    uint256 private _nextTokenId = 1;
    mapping(uint256 => Receipt) public receipts;

    event ReceiptMinted(
        uint256 indexed tokenId,
        address indexed granter,
        address indexed grantee,
        string scope,
        string tokenURI,
        string proofHash,
        uint256 expiresAt
    );

    event ReceiptRevoked(
        uint256 indexed tokenId,
        address indexed granter,
        address indexed grantee,
        uint256 revokedAt
    );

    constructor() ERC721("PermissionReceipt", "PRCPT") {}

    function mint(
        address granter,
        address to,
        string calldata scope,
        string calldata metadataURI,
        string calldata proofHash,
        uint256 expiresAt
    ) public returns (uint256 tokenId) {
        if (granter != msg.sender) {
            revert InvalidGranterCaller();
        }

        tokenId = _nextTokenId++;

        _safeMint(to, tokenId);
        _setTokenURI(tokenId, metadataURI);

        receipts[tokenId] = Receipt({
            granter: granter,
            grantee: to,
            scope: scope,
            proofHash: proofHash,
            issuedAt: block.timestamp,
            expiresAt: expiresAt,
            revokedAt: 0,
            active: true
        });

        emit ReceiptMinted(tokenId, granter, to, scope, metadataURI, proofHash, expiresAt);
    }

    function getPermission(uint256 tokenId) external view returns (Receipt memory receipt) {
        receipt = receipts[tokenId];

        if (!receipt.active) {
            revert InactivePermission();
        }

        if (receipt.expiresAt != 0 && block.timestamp > receipt.expiresAt) {
            revert PermissionExpired();
        }
    }

    function revoke(uint256 tokenId) external {
        Receipt storage receipt = receipts[tokenId];

        if (receipt.granter != msg.sender) {
            revert NotGranter();
        }

        address currentOwner = ownerOf(tokenId);

        receipt.active = false;
        receipt.revokedAt = block.timestamp;

        _burn(tokenId);

        emit ReceiptRevoked(tokenId, msg.sender, currentOwner, receipt.revokedAt);
    }

    function _update(
        address to,
        uint256 tokenId,
        address auth
    ) internal override returns (address) {
        address from = _ownerOf(tokenId);

        if (from != address(0) && to != address(0)) {
            revert Soulbound();
        }

        return super._update(to, tokenId, auth);
    }
}
