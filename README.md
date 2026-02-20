# PermChainOAuth

## Project Overview
Decentralized OAuth for crypto wallets with verifiable receipts—empowering self-sovereign permissions in Web3/AI.

PermChainOAuth is a decentralized wallet OAuth system where users grant and revoke app permissions through signed wallet interactions. Permission decisions are anchored on-chain as verifiable receipts, enabling transparent and auditable authorization for both Web3 and AI-native applications.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/traa-starr/PermChainOAuth.git
   cd PermChainOAuth
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Copy environment variables:
   ```bash
   cp .env.example .env
   ```
4. Start the development environment:
   ```bash
   npm run dev
   ```

## Usage
1. Connect a crypto wallet in the React frontend.
2. Request OAuth-like permissions for an app or agent.
3. Sign the permission grant transaction.
4. Store and verify on-chain permission receipts.
5. Use receipts to validate authorization in downstream services.

## Tech Stack
- **React** for the frontend UI and wallet interaction flows.
- **Solidity** for smart contracts managing permission receipts.
- **viem** for Ethereum JSON-RPC interactions and contract calls.
- **OpenZeppelin** for secure contract primitives and access patterns.

## Contributing
Contributions are welcome.

1. Fork the repository.
2. Create a feature branch:
   ```bash
   git checkout -b feat/your-feature
   ```
3. Commit your changes and push your branch.
4. Open a Pull Request describing your changes and motivation.

Please keep changes focused, add tests when applicable, and update documentation as needed.

## License
This project is licensed under the MIT License. See [LICENSE](./LICENSE) for details.
