// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title PermissionReceipt
/// @notice Soulbound ERC721 receipts that represent granted permissions.
/// @dev Tokens are non-transferable and can only be revoked (burned) by the original granter.
contract PermissionReceipt is ERC721, Ownable {
    /// @notice Stored permission details per token.
    struct PermissionData {
        address granter;
        string scope;
        uint256 expiry;
    }

    /// @notice Emitted when a permission receipt is minted.
    /// @param granter Address recorded as the permission granter.
    /// @param tokenId Newly minted token ID.
    /// @param scope Permission scope string.
    /// @param expiry Expiration timestamp.
    event PermissionGranted(address indexed granter, uint256 indexed tokenId, string scope, uint256 expiry);

    /// @notice Revert for any transfer or approval attempt on soulbound tokens.
    error Soulbound();

    uint256 private _nextTokenId = 1;
    mapping(uint256 tokenId => PermissionData data) private _permissionData;

    constructor() ERC721("PermissionReceipt", "PRC") Ownable(msg.sender) {}

    /// @notice Mints a non-transferable permission receipt.
    /// @dev Restricted to contract owner for basic access control.
    /// @param granter Address of the granter recorded on-chain and set as token holder.
    /// @param scope Human-readable permission scope (e.g. "read:documents").
    /// @param expiry Unix timestamp when this permission expires.
    /// @return tokenId The newly minted token ID.
    function mint(
        address granter,
        string calldata scope,
        uint256 expiry
    ) external onlyOwner returns (uint256 tokenId) {
        require(granter != address(0), "Invalid granter");

        tokenId = _nextTokenId++;
        _permissionData[tokenId] = PermissionData({granter: granter, scope: scope, expiry: expiry});

        _safeMint(granter, tokenId);
        emit PermissionGranted(granter, tokenId, scope, expiry);
    }

    /// @notice Revokes a permission by burning the corresponding token.
    /// @dev Only the original granter can revoke.
    /// @param tokenId Token ID to revoke.
    function revoke(uint256 tokenId) external {
        require(_ownerOf(tokenId) != address(0), "Token does not exist");
        require(msg.sender == _permissionData[tokenId].granter, "Only granter can revoke");

        _burn(tokenId);
        delete _permissionData[tokenId];
    }

    /// @notice Reads permission metadata for a token.
    /// @param tokenId Token ID to query.
    /// @return granter Address recorded as granter.
    /// @return scope Permission scope string.
    /// @return expiry Expiration timestamp.
    function getPermission(
        uint256 tokenId
    ) external view returns (address granter, string memory scope, uint256 expiry) {
        require(_ownerOf(tokenId) != address(0), "Token does not exist");

        PermissionData memory permission = _permissionData[tokenId];
        return (permission.granter, permission.scope, permission.expiry);
    }

    /// @inheritdoc ERC721
    /// @dev Blocks transfers while still allowing mints (from == 0) and burns (to == 0).
    function _update(address to, uint256 tokenId, address auth) internal virtual override returns (address from) {
        from = _ownerOf(tokenId);
        if (from != address(0) && to != address(0)) {
            revert Soulbound();
        }
        return super._update(to, tokenId, auth);
    }

    /// @inheritdoc ERC721
    function approve(address, uint256) public pure override {
        revert Soulbound();
    }

    /// @inheritdoc ERC721
    function setApprovalForAll(address, bool) public pure override {
        revert Soulbound();
    }
}
