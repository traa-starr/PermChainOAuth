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


## Offline Environments: Compiler Cache Required
Hardhat normally downloads Solidity compilers on demand. In restricted CI/Codex containers, this fails if outbound internet/DNS is blocked.

Use the cache script in an online environment first, then commit the generated cache files to this repo:

```bash
npm run cache:solc
```

This writes:
- `artifacts/cache/solc/list.json`
- `artifacts/cache/solc/soljson-v0.8.20+commit.a1b79de6.js`
- `artifacts/cache/solc/solc-build.json`

Then zip/ship the repository **with** `artifacts/cache/solc` so Hardhat can compile offline without downloading the compiler.

## Receipt Validity & Scope Model
- **Revocation is explicit state**, not burn-based truth. Calling `revoke(tokenId)` marks `active=false` and sets `revokedAt`, while the token remains queryable for audit/history.
- Receipts are still **soulbound** (non-transferable).
- Scopes are stored as `bytes32` hashes on-chain. Integrators can hash off-chain, or call the helper `scopeHash(string)`.

### Integrator validation flow
1. Compute the scope hash (`scopeHash("read:reports")` equivalent to `keccak256(bytes(scope))`).
2. Call:
   - `isValid(tokenId, requiredScopeHash, timestamp)` for canonical authorization checks.
   - `hasScopeHash(tokenId, scopeHash)` when you need direct scope membership checks.
3. Use `requiredScopeHash = 0x0` in `isValid` to skip scope requirement and validate only existence/revocation/expiry.

`isValid` returns `true` only if all are satisfied:
- token exists
- not revoked
- not expired (`expiresAt == 0` means no expiry)
- required scope is present (unless requiredScopeHash is zero)

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
