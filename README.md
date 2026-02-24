# PermChainOAuth

Decentralized OAuth for crypto wallets with verifiable on-chain permission receipts.

## Quickstart

1. **Clone and enter the repo (root directory):**
   ```bash
   git clone https://github.com/traa-starr/PermChainOAuth.git
   cd PermChainOAuth
   ```
2. **Install dependencies (root directory):**
   ```bash
   npm install
   ```
3. **Create `.env` safely (root directory):**
   ```bash
   npm run setup
   ```
   - This command is cross-platform (works on Windows/macOS/Linux).
   - It is idempotent: if `.env` already exists, it does nothing.
4. **Compile contracts (root directory):**
   ```bash
   npm run compile
   ```

## Smart Contracts (Hardhat)

All contract commands below run from the **repository root**.

- Run tests:
  ```bash
  npm test
  ```
- Start a local Hardhat JSON-RPC node:
  ```bash
  npm run node
  ```
- Deploy to an in-process Hardhat network (single command):
  ```bash
  npm run deploy:local
  ```
- Deploy to a running local node (start `npm run node` first in another terminal):
  ```bash
  npm run deploy:localhost
  ```

## PermissionReceipt authorization model

### Revocation model

- Receipts are **not burned** on revoke.
- Revocation is canonical on-chain state: `active=false` and `revokedAt` is set.
- Use `isValid(tokenId, requiredScopeHash, timestamp)` as the canonical authorization truth function; `isRevoked(tokenId)` and `exists(tokenId)` are convenience helpers.

### Expiry-at-mint policy

- This contract **allows minting already-expired receipts** (`expiresAt` in the past).
- Such receipts are still canonical historical records, but `isValid(...)` returns `false` immediately.
- Integrators should not infer authorization from mint success; always evaluate `isValid(...)`.

### Scopes are hashed on-chain

- Scopes are stored as `bytes32[] scopeHashes` per receipt at mint time.
- Use `scopeHash("read:reports")` (or equivalent off-chain keccak256 hashing) to derive scope hashes.
- Query checks:
  - `hasScopeHash(tokenId, scopeHash)`
  - `hasScope(tokenId, "read:reports")`

### Canonical validity checks for integrators

Existence semantics for helpers:

- `exists(tokenId)` returns whether the receipt NFT exists.
- For nonexistent receipts, `isRevoked`, `isExpired`, and `hasScopeHash` all return `false` (never ambiguous truthy reads).
- `getPermission` and `getScopeHashes` revert for nonexistent receipts with `NonexistentReceipt`.
  Use `isValid(tokenId, requiredScopeHash, timestamp)` as the only source of truth for authorization decisions.

`isValid` returns `true` only when all are satisfied:

1. token exists,
2. token is not revoked,
3. token is not expired (when `expiresAt != 0`),
4. required scope is present (unless `requiredScopeHash == bytes32(0)`, which skips scope requirement).

Recommended integration pattern:

- API/resource servers pass `requiredScopeHash` for the endpoint.
- For generic liveness checks (no scope), pass `bytes32(0)`.
- Use explicit timestamp for deterministic checks (e.g., replayed audits/simulations).

## Frontend

This repository currently includes React source files under `src/`, but it does **not** include a complete frontend build/dev-server configuration in the root project scripts yet.

Because of that, there is no supported `npm run dev` or `npm start` frontend command in this repo at this time.

## Usage

1. Deploy the `PermissionReceipt` contract.
2. Use the deployed contract address/ABI in your client integration.
3. Mint permission receipts and verify/revoke on-chain as needed.

## Tech Stack

- Hardhat
- Solidity
- OpenZeppelin Contracts

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE) for details.
