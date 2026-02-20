 codex/refine-frontend-integration-in-app.js
import { useMemo, useState } from "react";
import { ethers } from "ethers";

const LOCALHOST_CHAIN_ID = "0x539"; // 1337
const SEPOLIA_CHAIN_ID = "0xaa36a7"; // 11155111
const TARGET_CHAIN_ID =
  process.env.REACT_APP_USE_LOCAL === "true"
    ? LOCALHOST_CHAIN_ID
    : process.env.REACT_APP_CHAIN_ID || SEPOLIA_CHAIN_ID;

const NETWORK_PARAMS = {
  [SEPOLIA_CHAIN_ID]: {
    chainId: SEPOLIA_CHAIN_ID,
    chainName: "Sepolia",
    nativeCurrency: { name: "Sepolia ETH", symbol: "ETH", decimals: 18 },
    rpcUrls: ["https://rpc.sepolia.org"],
    blockExplorerUrls: ["https://sepolia.etherscan.io"],
  },
  [LOCALHOST_CHAIN_ID]: {
    chainId: LOCALHOST_CHAIN_ID,
    chainName: "Localhost 8545",
    nativeCurrency: { name: "ETH", symbol: "ETH", decimals: 18 },
    rpcUrls: ["http://127.0.0.1:8545"],
  },
};

const CONTRACT_ADDRESS = process.env.REACT_APP_CONTRACT_ADDRESS || "0xYourContractAddress";

// Full ABI for PermissionReceipt.sol (ERC721-compatible receipt token)
const CONTRACT_ABI = [
  { inputs: [], stateMutability: "nonpayable", type: "constructor" },
  { anonymous: false, inputs: [{ indexed: true, internalType: "address", name: "owner", type: "address" }, { indexed: true, internalType: "address", name: "approved", type: "address" }, { indexed: true, internalType: "uint256", name: "tokenId", type: "uint256" }], name: "Approval", type: "event" },
  { anonymous: false, inputs: [{ indexed: true, internalType: "address", name: "owner", type: "address" }, { indexed: true, internalType: "address", name: "operator", type: "address" }, { indexed: false, internalType: "bool", name: "approved", type: "bool" }], name: "ApprovalForAll", type: "event" },
  { anonymous: false, inputs: [{ indexed: true, internalType: "uint256", name: "tokenId", type: "uint256" }], name: "ReceiptRevoked", type: "event" },
  { anonymous: false, inputs: [{ indexed: true, internalType: "address", name: "from", type: "address" }, { indexed: true, internalType: "address", name: "to", type: "address" }, { indexed: true, internalType: "uint256", name: "tokenId", type: "uint256" }], name: "Transfer", type: "event" },
  { inputs: [{ internalType: "address", name: "to", type: "address" }, { internalType: "string", name: "uri", type: "string" }], name: "mintReceipt", outputs: [{ internalType: "uint256", name: "", type: "uint256" }], stateMutability: "nonpayable", type: "function" },
  { inputs: [{ internalType: "uint256", name: "tokenId", type: "uint256" }], name: "revoke", outputs: [], stateMutability: "nonpayable", type: "function" },
  { inputs: [{ internalType: "uint256", name: "tokenId", type: "uint256" }], name: "isRevoked", outputs: [{ internalType: "bool", name: "", type: "bool" }], stateMutability: "view", type: "function" },
  { inputs: [{ internalType: "address", name: "owner", type: "address" }], name: "balanceOf", outputs: [{ internalType: "uint256", name: "", type: "uint256" }], stateMutability: "view", type: "function" },
  { inputs: [{ internalType: "uint256", name: "tokenId", type: "uint256" }], name: "getApproved", outputs: [{ internalType: "address", name: "", type: "address" }], stateMutability: "view", type: "function" },
  { inputs: [{ internalType: "address", name: "owner", type: "address" }, { internalType: "address", name: "operator", type: "address" }], name: "isApprovedForAll", outputs: [{ internalType: "bool", name: "", type: "bool" }], stateMutability: "view", type: "function" },
  { inputs: [], name: "name", outputs: [{ internalType: "string", name: "", type: "string" }], stateMutability: "view", type: "function" },
  { inputs: [{ internalType: "uint256", name: "tokenId", type: "uint256" }], name: "ownerOf", outputs: [{ internalType: "address", name: "", type: "address" }], stateMutability: "view", type: "function" },
  { inputs: [{ internalType: "address", name: "from", type: "address" }, { internalType: "address", name: "to", type: "address" }, { internalType: "uint256", name: "tokenId", type: "uint256" }], name: "safeTransferFrom", outputs: [], stateMutability: "nonpayable", type: "function" },
  { inputs: [{ internalType: "address", name: "from", type: "address" }, { internalType: "address", name: "to", type: "address" }, { internalType: "uint256", name: "tokenId", type: "uint256" }, { internalType: "bytes", name: "data", type: "bytes" }], name: "safeTransferFrom", outputs: [], stateMutability: "nonpayable", type: "function" },
  { inputs: [{ internalType: "address", name: "operator", type: "address" }, { internalType: "bool", name: "approved", type: "bool" }], name: "setApprovalForAll", outputs: [], stateMutability: "nonpayable", type: "function" },
  { inputs: [{ internalType: "bytes4", name: "interfaceId", type: "bytes4" }], name: "supportsInterface", outputs: [{ internalType: "bool", name: "", type: "bool" }], stateMutability: "view", type: "function" },
  { inputs: [], name: "symbol", outputs: [{ internalType: "string", name: "", type: "string" }], stateMutability: "view", type: "function" },
  { inputs: [{ internalType: "uint256", name: "tokenId", type: "uint256" }], name: "tokenURI", outputs: [{ internalType: "string", name: "", type: "string" }], stateMutability: "view", type: "function" },
  { inputs: [{ internalType: "address", name: "from", type: "address" }, { internalType: "address", name: "to", type: "address" }, { internalType: "uint256", name: "tokenId", type: "uint256" }], name: "transferFrom", outputs: [], stateMutability: "nonpayable", type: "function" },
];

function App() {
  const [account, setAccount] = useState("");
  const [mintTo, setMintTo] = useState("");
  const [mintUri, setMintUri] = useState("");
  const [revokeTokenId, setRevokeTokenId] = useState("");
  const [status, setStatus] = useState("Disconnected");

  const provider = useMemo(() => {
    if (!window.ethereum) return null;
    return new ethers.BrowserProvider(window.ethereum);
  }, []);

  const switchToTargetNetwork = async () => {
    if (!window.ethereum) throw new Error("MetaMask not detected");

    const currentChainId = await window.ethereum.request({ method: "eth_chainId" });
    if (currentChainId === TARGET_CHAIN_ID) return;

    try {
      await window.ethereum.request({
        method: "wallet_switchEthereumChain",
        params: [{ chainId: TARGET_CHAIN_ID }],
      });
      setStatus(`Switched network to ${TARGET_CHAIN_ID}`);
    } catch (switchError) {
      if (switchError.code === 4902 && NETWORK_PARAMS[TARGET_CHAIN_ID]) {
        await window.ethereum.request({
          method: "wallet_addEthereumChain",
          params: [NETWORK_PARAMS[TARGET_CHAIN_ID]],
        });
        setStatus(`Added and switched network to ${TARGET_CHAIN_ID}`);
      } else {
        throw switchError;
      }
    }
  };

  const getContract = async () => {
    if (!provider) throw new Error("No injected wallet provider found");
    await switchToTargetNetwork();
    const signer = await provider.getSigner();
    return new ethers.Contract(CONTRACT_ADDRESS, CONTRACT_ABI, signer);
  };

  const connectWallet = async () => {
    try {
      if (!window.ethereum) throw new Error("Install MetaMask first");
      const accounts = await window.ethereum.request({ method: "eth_requestAccounts" });
      setAccount(accounts[0] || "");
      await switchToTargetNetwork();
      setStatus("Wallet connected");
    } catch (err) {
      setStatus(`Connect failed: ${err.shortMessage || err.message}`);

import React, { useMemo, useState } from 'react';
import {
  createPublicClient,
  createWalletClient,
  custom,
  getAddress,
  http,
  parseEther
} from 'viem';
import { hardhat } from 'viem/chains';
import { SiweMessage } from 'siwe';

const CONTRACT_ADDRESS = import.meta?.env?.VITE_RECEIPT_CONTRACT_ADDRESS || process.env.REACT_APP_RECEIPT_CONTRACT_ADDRESS || '';

// Replace this with the ABI from your Solidity contract once finalized.
const CONTRACT_ABI = [
  {
    inputs: [{ internalType: 'string', name: 'metadataURI', type: 'string' }],
    name: 'mintReceipt',
    outputs: [{ internalType: 'uint256', name: 'tokenId', type: 'uint256' }],
    stateMutability: 'nonpayable',
    type: 'function'
  }
];

function App() {
  const [account, setAccount] = useState('');
  const [siweSig, setSiweSig] = useState('');
  const [txHash, setTxHash] = useState('');
  const [metadataURI, setMetadataURI] = useState('ipfs://your-receipt-metadata');
  const [status, setStatus] = useState('Disconnected');

  const publicClient = useMemo(
    () =>
      createPublicClient({
        chain: hardhat,
        transport: http('http://127.0.0.1:8545')
      }),
    []
  );

  const connectWallet = async () => {
    if (!window.ethereum) {
      setStatus('No injected wallet detected. Install MetaMask or another EIP-1193 wallet.');
      return;
    }

    try {
      const walletClient = createWalletClient({
        chain: hardhat,
        transport: custom(window.ethereum)
      });

      const [selected] = await walletClient.requestAddresses();
      setAccount(getAddress(selected));
      setStatus('Wallet connected');
    } catch (error) {
      setStatus(`Wallet connection failed: ${error.message}`);
    }
  };

  const signInWithEthereum = async () => {
    if (!account) {
      setStatus('Connect wallet first');
      return;
    }

    try {
      const walletClient = createWalletClient({
        chain: hardhat,
        transport: custom(window.ethereum)
      });

      const message = new SiweMessage({
        domain: window.location.host,
        address: account,
        statement: 'Sign in to PermChain OAuth frontend',
        uri: window.location.origin,
        version: '1',
        chainId: hardhat.id,
        nonce: crypto.randomUUID().replace(/-/g, '').slice(0, 16)
      });

      const prepared = message.prepareMessage();
      const signature = await walletClient.signMessage({
        account,
        message: prepared
      });

      setSiweSig(signature);
      setStatus('SIWE message signed');
    } catch (error) {
      setStatus(`SIWE failed: ${error.message}`);
 main
    }
  };

  const mintReceipt = async () => {
 codex/refine-frontend-integration-in-app.js
    try {
      if (!mintTo || !mintUri) throw new Error("Recipient and URI are required");
      const contract = await getContract();

      setStatus("Mint tx submitted. Waiting for wallet confirmation...");
      const tx = await contract.mintReceipt(mintTo, mintUri);
      setStatus(`Mint tx sent: ${tx.hash}. Waiting for confirmation...`);

      const receipt = await tx.wait();
      setStatus(`Mint confirmed in block ${receipt.blockNumber}`);
    } catch (err) {
      setStatus(`Mint failed: ${err.shortMessage || err.message}`);
    }
  };

  const revokeReceipt = async () => {
    try {
      if (!revokeTokenId) throw new Error("Token ID is required");
      const contract = await getContract();

      setStatus("Revoke tx submitted. Waiting for wallet confirmation...");
      const tx = await contract.revoke(BigInt(revokeTokenId));
      setStatus(`Revoke tx sent: ${tx.hash}. Waiting for confirmation...`);

      const receipt = await tx.wait();
      setStatus(`Revoke confirmed in block ${receipt.blockNumber}`);
    } catch (err) {
      setStatus(`Revoke failed: ${err.shortMessage || err.message}`);

    if (!account) {
      setStatus('Connect wallet first');
      return;
    }

    if (!CONTRACT_ADDRESS) {
      setStatus('Missing contract address. Set REACT_APP_RECEIPT_CONTRACT_ADDRESS.');
      return;
    }

    try {
      const walletClient = createWalletClient({
        chain: hardhat,
        transport: custom(window.ethereum)
      });

      const hash = await walletClient.writeContract({
        address: CONTRACT_ADDRESS,
        abi: CONTRACT_ABI,
        functionName: 'mintReceipt',
        args: [metadataURI],
        account,
        // If your contract requires payment, set value accordingly.
        value: parseEther('0')
      });

      await publicClient.waitForTransactionReceipt({ hash });
      setTxHash(hash);
      setStatus('Receipt minted successfully');
    } catch (error) {
      setStatus(`Mint failed: ${error.message}`);
 main
    }
  };

  return (
 codex/refine-frontend-integration-in-app.js
    <div style={{ maxWidth: 680, margin: "2rem auto", fontFamily: "Arial, sans-serif" }}>
      <h2>Permission Receipt DApp</h2>

      <button onClick={connectWallet}>Connect Wallet</button>
      <p><strong>Account:</strong> {account || "Not connected"}</p>
      <p><strong>Status:</strong> {status}</p>

      <hr />
      <h3>Mint Receipt</h3>
      <input
        type="text"
        value={mintTo}
        onChange={(e) => setMintTo(e.target.value)}
        placeholder="Recipient address"
        style={{ width: "100%", marginBottom: "0.5rem" }}
      />
      <input
        type="text"
        value={mintUri}
        onChange={(e) => setMintUri(e.target.value)}
        placeholder="Token URI"
        style={{ width: "100%", marginBottom: "0.5rem" }}
      />
      <button onClick={mintReceipt}>Mint Receipt</button>

      <hr />
      <h3>Revoke Receipt</h3>
      <input
        type="number"
        min="0"
        step="1"
        value={revokeTokenId}
        onChange={(e) => setRevokeTokenId(e.target.value)}
        placeholder="Token ID"
        style={{ width: "100%", marginBottom: "0.5rem" }}
      />
      <button onClick={revokeReceipt}>Revoke Receipt</button>
    </div>

    <main style={{ fontFamily: 'Arial, sans-serif', maxWidth: 760, margin: '3rem auto', lineHeight: 1.5 }}>
      <h1>PermChain OAuth Frontend (Initial Integration)</h1>

      <section style={{ marginBottom: '1.5rem' }}>
        <button onClick={connectWallet}>Connect Wallet</button>
        <p><strong>Account:</strong> {account || 'Not connected'}</p>
      </section>

      <section style={{ marginBottom: '1.5rem' }}>
        <button onClick={signInWithEthereum} disabled={!account}>Sign SIWE Message</button>
        <p style={{ wordBreak: 'break-all' }}><strong>Signature:</strong> {siweSig || 'Not signed yet'}</p>
      </section>

      <section style={{ marginBottom: '1.5rem' }}>
        <label htmlFor="metadataURI"><strong>Receipt Metadata URI</strong></label>
        <input
          id="metadataURI"
          style={{ width: '100%', marginTop: 8, marginBottom: 12, padding: 8 }}
          value={metadataURI}
          onChange={(e) => setMetadataURI(e.target.value)}
          placeholder="ipfs://..."
        />
        <button onClick={mintReceipt} disabled={!account}>Mint Receipt</button>
        <p style={{ wordBreak: 'break-all' }}><strong>Tx Hash:</strong> {txHash || 'No mint transaction submitted'}</p>
      </section>

      <p><strong>Status:</strong> {status}</p>
    </main>
 main
  );
}

export default App;
