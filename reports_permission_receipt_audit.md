# PermissionReceipt.sol Audit Report

## Scope
- Contract: `contracts/PermissionReceipt.sol`
- Compiler: `^0.8.20`
- Focus areas: reentrancy, overflow/underflow, access control, expiry/ZKP logic, and ERC721 override behavior.

## Findings

### 1) Mint can write an already-expired permission
- **Severity:** Low
- **Where:** `mint(..., uint256 expiresAt)`
- **Details:** The contract allows minting with `expiresAt` in the past. The permission becomes unusable immediately in `getPermission`, but mint still emits `ReceiptMinted` and stores an active receipt until a revoke/burn. This can produce noisy state and ambiguous analytics.
- **Recommendation:** Add validation in `mint`:
  - `require(expiresAt == 0 || expiresAt > block.timestamp, "Invalid expiry");`

### 2) Revocation requires token ownership to exist at call-time
- **Severity:** Medium
- **Where:** `revoke(uint256 tokenId)`
- **Details:** `revoke` calls `ownerOf(tokenId)`, which reverts if token is already burned/non-existent. That means a granter cannot idempotently revoke once burned, and error surface is less explicit.
- **Recommendation:**
  - Add explicit existence check and custom error for already revoked/nonexistent token.
  - Consider idempotent semantics (no-op if already inactive).

### 3) External call ordering in mint (reentrancy hardening)
- **Severity:** Low
- **Where:** `mint` around `_safeMint`
- **Details:** `_safeMint` may call `onERC721Received` on receiver contracts before `receipts[tokenId]` is populated. Current access control blocks direct abuse (`granter == msg.sender`), so practical exploitability is low, but CEI ordering is not ideal.
- **Recommendation:**
  - Prefer `_mint` for EOAs only if acceptable, or
  - Record receipt state before external interaction and/or apply `ReentrancyGuard`.

### 4) Access-control model is intentionally self-asserted granter
- **Severity:** Informational
- **Where:** `mint`, `revoke`
- **Details:** Any address can mint receipts as granter only for itself (`granter == msg.sender`), and only the same granter can revoke. This is coherent for decentralized self-issued grants, but not for centrally-administered policy systems.
- **Recommendation:** If centralized governance is intended, gate `mint/revoke` with `Ownable`, `AccessControl`, or role manager.

### 5) Expiry state is validated only in getter path
- **Severity:** Low
- **Where:** `getPermission`
- **Details:** Expired permissions remain marked `active=true` in storage unless revoked. Off-chain indexers reading `receipts(tokenId)` directly can misinterpret stale grants.
- **Recommendation:**
  - Add `isValid(tokenId)` view helper that computes active + non-expired.
  - Optionally add `sweepExpired(tokenId)`/lazy deactivation.

### 6) ERC721 soulbound override behavior is correct but strict
- **Severity:** Informational
- **Where:** `_update`
- **Details:** Blocking when `from != 0 && to != 0` correctly prevents transfers while still allowing mint (`from=0`) and burn (`to=0`). This matches soulbound intent.
- **Recommendation:** Keep override; optionally emit explicit transfer-blocked custom error docs in README for integrators.

### 7) Overflow/underflow
- **Severity:** Informational
- **Where:** `_nextTokenId++`
- **Details:** Solidity `^0.8.20` has built-in checked arithmetic, so no SafeMath dependency is needed.
- **Recommendation:** None required.

### 8) ZKP/proof binding quality
- **Severity:** Medium
- **Where:** `proofHash` as free-form string
- **Details:** Contract stores `proofHash` but does not verify proof validity, domain separation, signer binding, or uniqueness. Security depends entirely on off-chain verifier discipline.
- **Recommendation:**
  - Standardize `proofHash = keccak256(abi.encode(domain, chainId, contract, granter, grantee, scope, nonce, expiry))`.
  - Add optional on-chain nullifier/nonce tracking to prevent replay.

## Overall Risk
- **Overall rating:** **Medium**
- Core logic is compact and mostly safe for soulbound receipt issuance. Main concerns are operational consistency (expired-but-active state), explicitness around revocation semantics, and off-chain proof rigor.
