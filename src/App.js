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
    }
  };

  const mintReceipt = async () => {
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
    }
  };

  return (
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
  );
}

export default App;
