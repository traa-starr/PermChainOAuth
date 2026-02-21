import React, { useMemo, useState } from 'react';
import {
  createPublicClient,
  createWalletClient,
  custom,
  getAddress,
  http,
  isAddress,
  parseAbi,
} from 'viem';
import { sepolia } from 'viem/chains';
import { SiweMessage } from 'siwe';

const SEPOLIA_RPC_URL =
  process.env.REACT_APP_SEPOLIA_RPC_URL ||
  'https://eth-sepolia.g.alchemy.com/v2/your-api-key';
const CONTRACT_ADDRESS = process.env.REACT_APP_RECEIPT_CONTRACT_ADDRESS || '';

const AI_SCOPES = ['read_balance', 'ai:train_data', 'ai:read_health'];

// Full ABI for contracts/PermissionReceipt.sol (including inherited ERC721/URIStorage interfaces)
const CONTRACT_ABI = [
  {
    inputs: [],
    stateMutability: 'nonpayable',
    type: 'constructor',
  },
  {
    inputs: [
      {
        internalType: 'address',
        name: 'operator',
        type: 'address',
      },
      {
        internalType: 'uint256',
        name: 'tokenId',
        type: 'uint256',
      },
    ],
    name: 'ERC721InsufficientApproval',
    type: 'error',
  },
  {
    inputs: [
      {
        internalType: 'address',
        name: 'sender',
        type: 'address',
      },
      {
        internalType: 'uint256',
        name: 'tokenId',
        type: 'uint256',
      },
      {
        internalType: 'address',
        name: 'owner',
        type: 'address',
      },
    ],
    name: 'ERC721IncorrectOwner',
    type: 'error',
  },
  {
    inputs: [
      {
        internalType: 'address',
        name: 'operator',
        type: 'address',
      },
    ],
    name: 'ERC721InvalidApprover',
    type: 'error',
  },
  {
    inputs: [
      {
        internalType: 'address',
        name: 'owner',
        type: 'address',
      },
    ],
    name: 'ERC721InvalidOwner',
    type: 'error',
  },
  {
    inputs: [
      {
        internalType: 'address',
        name: 'receiver',
        type: 'address',
      },
    ],
    name: 'ERC721InvalidReceiver',
    type: 'error',
  },
  {
    inputs: [
      {
        internalType: 'address',
        name: 'sender',
        type: 'address',
      },
    ],
    name: 'ERC721InvalidSender',
    type: 'error',
  },
  {
    inputs: [
      {
        internalType: 'uint256',
        name: 'tokenId',
        type: 'uint256',
      },
    ],
    name: 'ERC721NonexistentToken',
    type: 'error',
  },
  {
    inputs: [],
    name: 'NotGranter',
    type: 'error',
  },
  {
    inputs: [],
    name: 'Soulbound',
    type: 'error',
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: 'address',
        name: 'owner',
        type: 'address',
      },
      {
        indexed: true,
        internalType: 'address',
        name: 'approved',
        type: 'address',
      },
      {
        indexed: true,
        internalType: 'uint256',
        name: 'tokenId',
        type: 'uint256',
      },
    ],
    name: 'Approval',
    type: 'event',
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: 'address',
        name: 'owner',
        type: 'address',
      },
      {
        indexed: true,
        internalType: 'address',
        name: 'operator',
        type: 'address',
      },
      {
        indexed: false,
        internalType: 'bool',
        name: 'approved',
        type: 'bool',
      },
    ],
    name: 'ApprovalForAll',
    type: 'event',
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: 'uint256',
        name: 'tokenId',
        type: 'uint256',
      },
      {
        indexed: true,
        internalType: 'address',
        name: 'granter',
        type: 'address',
      },
      {
        indexed: true,
        internalType: 'address',
        name: 'grantee',
        type: 'address',
      },
      {
        indexed: false,
        internalType: 'string',
        name: 'scope',
        type: 'string',
      },
      {
        indexed: false,
        internalType: 'string',
        name: 'tokenURI',
        type: 'string',
      },
    ],
    name: 'ReceiptMinted',
    type: 'event',
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: 'uint256',
        name: 'tokenId',
        type: 'uint256',
      },
      {
        indexed: true,
        internalType: 'address',
        name: 'granter',
        type: 'address',
      },
      {
        indexed: true,
        internalType: 'address',
        name: 'grantee',
        type: 'address',
      },
      {
        indexed: false,
        internalType: 'uint256',
        name: 'revokedAt',
        type: 'uint256',
      },
    ],
    name: 'ReceiptRevoked',
    type: 'event',
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: 'address',
        name: 'from',
        type: 'address',
      },
      {
        indexed: true,
        internalType: 'address',
        name: 'to',
        type: 'address',
      },
      {
        indexed: true,
        internalType: 'uint256',
        name: 'tokenId',
        type: 'uint256',
      },
    ],
    name: 'Transfer',
    type: 'event',
  },
  {
    inputs: [
      {
        internalType: 'address',
        name: 'owner',
        type: 'address',
      },
    ],
    name: 'balanceOf',
    outputs: [
      {
        internalType: 'uint256',
        name: '',
        type: 'uint256',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [
      {
        internalType: 'uint256',
        name: 'tokenId',
        type: 'uint256',
      },
    ],
    name: 'getApproved',
    outputs: [
      {
        internalType: 'address',
        name: '',
        type: 'address',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [
      {
        internalType: 'address',
        name: 'owner',
        type: 'address',
      },
      {
        internalType: 'address',
        name: 'operator',
        type: 'address',
      },
    ],
    name: 'isApprovedForAll',
    outputs: [
      {
        internalType: 'bool',
        name: '',
        type: 'bool',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [
      {
        internalType: 'address',
        name: 'to',
        type: 'address',
      },
      {
        internalType: 'string',
        name: 'scope',
        type: 'string',
      },
      {
        internalType: 'string',
        name: 'metadataURI',
        type: 'string',
      },
    ],
    name: 'mint',
    outputs: [
      {
        internalType: 'uint256',
        name: 'tokenId',
        type: 'uint256',
      },
    ],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [],
    name: 'name',
    outputs: [
      {
        internalType: 'string',
        name: '',
        type: 'string',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [
      {
        internalType: 'uint256',
        name: 'tokenId',
        type: 'uint256',
      },
    ],
    name: 'ownerOf',
    outputs: [
      {
        internalType: 'address',
        name: '',
        type: 'address',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [
      {
        internalType: 'uint256',
        name: '',
        type: 'uint256',
      },
    ],
    name: 'receipts',
    outputs: [
      {
        internalType: 'address',
        name: 'granter',
        type: 'address',
      },
      {
        internalType: 'address',
        name: 'grantee',
        type: 'address',
      },
      {
        internalType: 'string',
        name: 'scope',
        type: 'string',
      },
      {
        internalType: 'uint256',
        name: 'issuedAt',
        type: 'uint256',
      },
      {
        internalType: 'uint256',
        name: 'revokedAt',
        type: 'uint256',
      },
      {
        internalType: 'bool',
        name: 'active',
        type: 'bool',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [
      {
        internalType: 'uint256',
        name: 'tokenId',
        type: 'uint256',
      },
    ],
    name: 'revoke',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [
      {
        internalType: 'address',
        name: 'from',
        type: 'address',
      },
      {
        internalType: 'address',
        name: 'to',
        type: 'address',
      },
      {
        internalType: 'uint256',
        name: 'tokenId',
        type: 'uint256',
      },
    ],
    name: 'safeTransferFrom',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [
      {
        internalType: 'address',
        name: 'from',
        type: 'address',
      },
      {
        internalType: 'address',
        name: 'to',
        type: 'address',
      },
      {
        internalType: 'uint256',
        name: 'tokenId',
        type: 'uint256',
      },
      {
        internalType: 'bytes',
        name: 'data',
        type: 'bytes',
      },
    ],
    name: 'safeTransferFrom',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [
      {
        internalType: 'address',
        name: 'operator',
        type: 'address',
      },
      {
        internalType: 'bool',
        name: 'approved',
        type: 'bool',
      },
    ],
    name: 'setApprovalForAll',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [
      {
        internalType: 'bytes4',
        name: 'interfaceId',
        type: 'bytes4',
      },
    ],
    name: 'supportsInterface',
    outputs: [
      {
        internalType: 'bool',
        name: '',
        type: 'bool',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [],
    name: 'symbol',
    outputs: [
      {
        internalType: 'string',
        name: '',
        type: 'string',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [
      {
        internalType: 'uint256',
        name: 'tokenId',
        type: 'uint256',
      },
    ],
    name: 'tokenURI',
    outputs: [
      {
        internalType: 'string',
        name: '',
        type: 'string',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [
      {
        internalType: 'address',
        name: 'from',
        type: 'address',
      },
      {
        internalType: 'address',
        name: 'to',
        type: 'address',
      },
      {
        internalType: 'uint256',
        name: 'tokenId',
        type: 'uint256',
      },
    ],
    name: 'transferFrom',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
];

const GET_PERMISSION_ABI = parseAbi([
  'function getPermission(uint256 tokenId) view returns (address granter, address grantee, string scope, uint256 issuedAt, uint256 revokedAt, bool active, bytes32 proofHash)',
]);

function App() {
  const [account, setAccount] = useState('');
  const [selectedScope, setSelectedScope] = useState(AI_SCOPES[0]);
  const [mintTo, setMintTo] = useState('');
  const [metadataURI, setMetadataURI] = useState('ipfs://permchain/receipt-metadata');
  const [tokenId, setTokenId] = useState('');
  const [siweSig, setSiweSig] = useState('');
  const [lastTxHash, setLastTxHash] = useState('');
  const [permissionData, setPermissionData] = useState(null);
  const [status, setStatus] = useState('Disconnected');

  const publicClient = useMemo(
    () =>
      createPublicClient({
        chain: sepolia,
        transport: http(SEPOLIA_RPC_URL),
      }),
    []
  );

  const makeWalletClient = () => {
    if (!window.ethereum) {
      throw new Error('No injected wallet found. Install MetaMask or another EIP-1193 wallet.');
    }
    return createWalletClient({
      chain: sepolia,
      transport: custom(window.ethereum),
    });
  };

  const switchToSepolia = async () => {
    try {
      const walletClient = makeWalletClient();
      setStatus('Requesting wallet network switch to Sepolia...');
      await walletClient.switchChain({ id: sepolia.id });
      setStatus('Wallet is now on Sepolia.');
    } catch (error) {
      setStatus(`Network switch failed: ${error.message}`);
    }
  };

  const connectWallet = async () => {
    try {
      const walletClient = makeWalletClient();
      const [selected] = await walletClient.requestAddresses();
      const checksumAddress = getAddress(selected);
      setAccount(checksumAddress);
      if (!mintTo) {
        setMintTo(checksumAddress);
      }
      setStatus(`Wallet connected: ${checksumAddress}`);
    } catch (error) {
      setStatus(`Wallet connection failed: ${error.message}`);
    }
  };

  const signInWithEthereum = async () => {
    if (!account) {
      setStatus('Connect wallet first.');
      return;
    }

    try {
      const walletClient = makeWalletClient();
      const message = new SiweMessage({
        domain: window.location.host,
        address: account,
        statement: `Authorize PermChain OAuth for scope: ${selectedScope}. Future-proofed for zk attestations (proofHash).`,
        uri: window.location.origin,
        version: '1',
        chainId: sepolia.id,
        nonce: crypto.randomUUID().replace(/-/g, '').slice(0, 16),
      });

      const signature = await walletClient.signMessage({
        account,
        message: message.prepareMessage(),
      });

      setSiweSig(signature);
      setStatus('SIWE message signed successfully.');
    } catch (error) {
      setStatus(`SIWE signing failed: ${error.message}`);
    }
  };

  const validateContractConfig = () => {
    if (!account) {
      throw new Error('Connect wallet first.');
    }
    if (!CONTRACT_ADDRESS || !isAddress(CONTRACT_ADDRESS)) {
      throw new Error('Set a valid REACT_APP_RECEIPT_CONTRACT_ADDRESS in your env.');
    }
  };

  const mintReceipt = async () => {
    try {
      validateContractConfig();
      if (!isAddress(mintTo)) {
        throw new Error('Enter a valid recipient address.');
      }
      if (!metadataURI) {
        throw new Error('Metadata URI is required.');
      }

      const walletClient = makeWalletClient();
      setStatus('Submitting mint transaction...');

      const hash = await walletClient.writeContract({
        address: getAddress(CONTRACT_ADDRESS),
        abi: CONTRACT_ABI,
        functionName: 'mint',
        account,
        args: [getAddress(mintTo), selectedScope, metadataURI],
      });

      setLastTxHash(hash);
      setStatus(`Mint submitted (${hash}). Waiting for confirmations...`);

      const receipt = await publicClient.waitForTransactionReceipt({ hash, confirmations: 1 });
      setStatus(`Mint confirmed in block ${receipt.blockNumber.toString()}.`);
    } catch (error) {
      setStatus(`Mint failed: ${error.message}`);
    }
  };

  const revokeReceipt = async () => {
    try {
      validateContractConfig();
      if (!tokenId) {
        throw new Error('Token ID is required to revoke.');
      }

      const walletClient = makeWalletClient();
      const tokenIdBigInt = BigInt(tokenId);

      setStatus('Submitting revoke transaction...');
      const hash = await walletClient.writeContract({
        address: getAddress(CONTRACT_ADDRESS),
        abi: CONTRACT_ABI,
        functionName: 'revoke',
        account,
        args: [tokenIdBigInt],
      });

      setLastTxHash(hash);
      setStatus(`Revoke submitted (${hash}). Waiting for confirmations...`);

      const receipt = await publicClient.waitForTransactionReceipt({ hash, confirmations: 1 });
      setStatus(`Revoke confirmed in block ${receipt.blockNumber.toString()}.`);
    } catch (error) {
      setStatus(`Revoke failed: ${error.message}`);
    }
  };

  const getPermission = async () => {
    try {
      validateContractConfig();
      if (!tokenId) {
        throw new Error('Token ID is required.');
      }

      const tokenIdBigInt = BigInt(tokenId);
      setStatus(`Loading permission data for token #${tokenId}...`);

      let permission;
      try {
        permission = await publicClient.readContract({
          address: getAddress(CONTRACT_ADDRESS),
          abi: GET_PERMISSION_ABI,
          functionName: 'getPermission',
          args: [tokenIdBigInt],
        });
      } catch {
        const fallback = await publicClient.readContract({
          address: getAddress(CONTRACT_ADDRESS),
          abi: CONTRACT_ABI,
          functionName: 'receipts',
          args: [tokenIdBigInt],
        });
        permission = [...fallback, '0x0000000000000000000000000000000000000000000000000000000000000000'];
      }

      const [granter, grantee, scope, issuedAt, revokedAt, active, proofHash] = permission;
      setPermissionData({
        granter,
        grantee,
        scope,
        issuedAt: Number(issuedAt),
        revokedAt: Number(revokedAt),
        active,
        proofHash,
      });
      setStatus(`Permission loaded for token #${tokenId}.`);
    } catch (error) {
      setPermissionData(null);
      setStatus(`Permission lookup failed: ${error.message}`);
    }
  };

  return (
    <main style={{ fontFamily: 'Arial, sans-serif', maxWidth: 780, margin: '2rem auto', lineHeight: 1.5 }}>
      <h1>PermChain OAuth Frontend (Viem + SIWE + AI Scopes)</h1>

      <p>
        <strong>Contract:</strong> {CONTRACT_ADDRESS || 'Not configured'}
        <br />
        <strong>RPC:</strong> {SEPOLIA_RPC_URL}
      </p>

      <section style={{ marginBottom: 16 }}>
        <button onClick={connectWallet}>Connect Wallet</button>{' '}
        <button onClick={switchToSepolia}>Switch to Sepolia</button>
        <p>
          <strong>Account:</strong> {account || 'Not connected'}
        </p>
      </section>

      <section style={{ marginBottom: 16 }}>
        <label htmlFor="scope">
          <strong>AI Scope</strong>
        </label>
        <select
          id="scope"
          value={selectedScope}
          onChange={(event) => setSelectedScope(event.target.value)}
          style={{ display: 'block', marginTop: 8, marginBottom: 8, padding: 8, width: '100%' }}
        >
          {AI_SCOPES.map((scope) => (
            <option key={scope} value={scope}>
              {scope}
            </option>
          ))}
        </select>
        <button onClick={signInWithEthereum} disabled={!account}>
          Sign SIWE Message
        </button>
        <p style={{ wordBreak: 'break-all' }}>
          <strong>Signature:</strong> {siweSig || 'Not signed'}
        </p>
      </section>

      <section style={{ marginBottom: 16 }}>
        <h3>Mint Permission Receipt</h3>
        <input
          placeholder="Recipient address"
          value={mintTo}
          onChange={(event) => setMintTo(event.target.value)}
          style={{ display: 'block', width: '100%', marginBottom: 8, padding: 8 }}
        />
        <input
          placeholder="Metadata URI (ipfs://...)"
          value={metadataURI}
          onChange={(event) => setMetadataURI(event.target.value)}
          style={{ display: 'block', width: '100%', marginBottom: 8, padding: 8 }}
        />
        <button onClick={mintReceipt} disabled={!account}>
          Mint Receipt
        </button>
      </section>

      <section style={{ marginBottom: 16 }}>
        <h3>Revoke or Inspect Receipt</h3>
        <input
          placeholder="Token ID"
          value={tokenId}
          onChange={(event) => setTokenId(event.target.value)}
          style={{ display: 'block', width: '100%', marginBottom: 8, padding: 8 }}
        />
        <button onClick={revokeReceipt} disabled={!account}>
          Revoke Receipt
        </button>{' '}
        <button onClick={getPermission} disabled={!account}>
          Get Permission
        </button>
      </section>

      <section style={{ marginBottom: 16 }}>
        <h3>Permission Data</h3>
        {permissionData ? (
          <ul>
            <li>Granter: {permissionData.granter}</li>
            <li>Grantee: {permissionData.grantee}</li>
            <li>Scope: {permissionData.scope}</li>
            <li>Active: {permissionData.active ? 'true' : 'false'}</li>
            <li>Issued: {new Date(permissionData.issuedAt * 1000).toISOString()}</li>
            <li>
              Revoked:{' '}
              {permissionData.revokedAt > 0
                ? new Date(permissionData.revokedAt * 1000).toISOString()
                : 'Not revoked'}
            </li>
            <li>proofHash (zk-ready): {permissionData.proofHash}</li>
          </ul>
        ) : (
          <p>No token loaded.</p>
        )}
      </section>

      <p style={{ wordBreak: 'break-all' }}>
        <strong>Last tx hash:</strong> {lastTxHash || 'None'}
      </p>
      <p>
        <strong>Status:</strong> {status}
      </p>
      {lastTxHash && (
        <p>
          <strong>Explorer:</strong>{' '}
          <a href={`https://sepolia.etherscan.io/tx/${lastTxHash}`} target="_blank" rel="noreferrer">
            View transaction
          </a>
        </p>
      )}
      <p style={{ color: '#666' }}>
        2026 prep note: proofHash display is included for future zk-permission attestations.
      </p>
    </main>
  );
}

export default App;
