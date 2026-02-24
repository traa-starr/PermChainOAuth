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


## How the bridge maps to OAuth
- **Authorization grant**: the on-chain `PermissionReceipt` token/receipt.
- **Authorization server**: this Node bridge validates SIWE + chain state.
- **Access token**: short-lived JWT returned by `/token`.
- **Token introspection**: `/introspect` re-checks receipt validity and scope hash.
- **Resource server**: `/data` example endpoint requiring an active token + scope.

See [docs/bridge.md](./docs/bridge.md) for full nonce → authorize → wallet mint → token → introspect flow.
