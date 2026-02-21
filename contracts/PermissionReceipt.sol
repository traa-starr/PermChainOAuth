// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {ERC721URIStorage} from "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";

contract PermissionReceipt is ERC721URIStorage {
    error NotGranter();
    error Soulbound();

    struct Receipt {
        address granter;
        address grantee;
        string scope;
        uint256 issuedAt;
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
        string tokenURI
    );

    event ReceiptRevoked(
        uint256 indexed tokenId,
        address indexed granter,
        address indexed grantee,
        uint256 revokedAt
    );

    constructor() ERC721("PermissionReceipt", "PRCPT") {}

    function mint(
        address to,
        string calldata scope,
        string calldata metadataURI
    ) external returns (uint256 tokenId) {
        tokenId = _nextTokenId++;

        _safeMint(to, tokenId);
        _setTokenURI(tokenId, metadataURI);

        receipts[tokenId] = Receipt({
            granter: msg.sender,
            grantee: to,
            scope: scope,
            issuedAt: block.timestamp,
            revokedAt: 0,
            active: true
        });

        emit ReceiptMinted(tokenId, msg.sender, to, scope, metadataURI);
    }

    function revoke(uint256 tokenId) external {
        Receipt storage receipt = receipts[tokenId];

        if (receipt.granter != msg.sender) {
            revert NotGranter();
        }

        // ownerOf() reverts if token doesn't exist, which is acceptable here.
        address currentOwner = ownerOf(tokenId);

        receipt.active = false;
        receipt.revokedAt = block.timestamp;

        _burn(tokenId);

        emit ReceiptRevoked(tokenId, msg.sender, currentOwner, receipt.revokedAt);
    }

    // Soulbound enforcement: allow mint (from == 0) and burn (to == 0),
    // block transfers (from != 0 && to != 0).
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