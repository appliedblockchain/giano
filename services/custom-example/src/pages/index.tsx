import React, { type FormEvent } from 'react';
import { useEffect, useState } from 'react';
import { privateErc20Abi } from '@appliedblockchain/giano-contracts';
import type { NextPage } from 'next';
import Head from 'next/head';
import { formatEther, parseEther, encodeFunctionData } from 'viem';
import { useAccount, useConnect, useDisconnect, useReadContract, useSendTransaction, useWalletClient, useWriteContract } from 'wagmi';
import { config, type SupportedEntryPointVersion } from '../config';
// Remove static connector import since we'll use dynamic connectors
// import { gianoConnector } from '../wagmi';
import styles from '../styles/Home.module.css';
import { EntryPointSelector } from '../components/EntryPointSelector';
import { EntryPointVerification } from '../components/EntryPointVerification';
import { WalletImplementationManager } from '../components/WalletImplementationManager';
import { useDynamicWagmi } from '../providers/WagmiProvider';

const Home: NextPage = () => {
  const [mounted, setMounted] = useState(false);
  const [connectionReady, setConnectionReady] = useState(false);
  const [isAuthenticating, setIsAuthenticating] = useState(false);
  
  // Use dynamic wagmi context instead of local state
  const { selectedEntryPointVersion, setSelectedEntryPointVersion, isReconfiguring } = useDynamicWagmi();
  
  // Track wallet implementation version (separate from bundler EntryPoint version)
  const [walletImplementationVersion, setWalletImplementationVersion] = useState<SupportedEntryPointVersion>('0.7');
  
  const { connect, connectors } = useConnect();
  const { disconnect } = useDisconnect();
  const { address, isConnected, status } = useAccount();
  const { data: walletClient } = useWalletClient();
  const { writeContractAsync, isPending: isWritePending } = useWriteContract();
  const { sendTransaction } = useSendTransaction();
  const {
    refetch: readContract,
    isFetching: isReadFetching,
    error,
  } = useReadContract({
    address: config.privateErc20Address as `0x${string}`,
    abi: privateErc20Abi,
    functionName: 'balanceOf',
    args: [address!],
    query: {
      enabled: false,
      retry: false,
      retryOnMount: false,
    },
  });
  const [inputMessage, setInputMessage] = useState('');
  const [manualMintAmount, setManualMintAmount] = useState('');
  const [contractState, setContractState] = useState<bigint | null>(null);
  const [privateContractState, setPrivateContractState] = useState<bigint | null>(null);
  const [isPrivateBalanceFetching, setIsPrivateBalanceFetching] = useState(false);
  const [signatureResult, setSignatureResult] = useState<string>('');
  const [messageToSign, setMessageToSign] = useState('Hello, please sign this message!');
  const [isManualMintPending, setIsManualMintPending] = useState(false);
  const [preparedUserOp, setPreparedUserOp] = useState<any>(null);
  const [isUserOpSigned, setIsUserOpSigned] = useState(false);

  // Helper function to delete passkey (clear all data including passkey)
  const deletePasskey = async () => {
    if (!confirm('⚠️ This will permanently delete your passkey data. You will lose access to your wallet and need to create a new passkey to reconnect. Continue?')) {
      return;
    }

    try {
      // Disconnect first if connected
      if (isConnected) {
        disconnect();
      }

      // Clear all localStorage data including passkey
      localStorage.removeItem('giano_credential_id');
      localStorage.removeItem('giano_account_address');
      localStorage.removeItem('gpk-passkey-id');

      // Clear all public key entries (gpk-* pattern)
      const keysToRemove: string[] = [];
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && key.startsWith('gpk-')) {
          keysToRemove.push(key);
        }
      }
      keysToRemove.forEach(key => localStorage.removeItem(key));

      console.log('Passkey deleted successfully');
    } catch (error) {
      console.error('Failed to delete passkey:', error);
    }
  };

  useEffect(() => {
    setMounted(true);
  }, []);

  // Auto-connect effect for session restoration with authentication
  useEffect(() => {
    if (mounted && !isConnected && !isAuthenticating) {
      const storedCredentialId = localStorage.getItem('giano_credential_id');
      const storedAccountAddress = localStorage.getItem('giano_account_address');

      if (storedCredentialId && storedAccountAddress) {
        // Attempt to restore session with authentication
        const connectAsync = async () => {
          try {
            setIsAuthenticating(true);
            const response = connect({ connector: connectors[0] }); // Assuming the first connector is the one to restore
          } catch (error) {
            console.warn('Failed to auto-restore session:', error);
            // Clear invalid stored data
            localStorage.removeItem('giano_credential_id');
            localStorage.removeItem('giano_account_address');
          } finally {
            setIsAuthenticating(false);
          }
        };
        void connectAsync();
      }
    }
  }, [mounted, isConnected, connect, isAuthenticating, connectors]);

  // Wait for the connection to be fully established before allowing contract calls
  useEffect(() => {
    if (isConnected && address && status === 'connected' && !isAuthenticating) {
      // Add a small delay to ensure the smart account is fully initialized
      const timer = setTimeout(() => {
        setConnectionReady(true);
      }, 500);
      return () => clearTimeout(timer);
    } else {
      setConnectionReady(false);
    }
  }, [isConnected, address, status, isAuthenticating]);

  useEffect(() => {
    if (error) {
      console.error(error);
    }
  }, [error]);

  const sendTx = async (e: FormEvent & { currentTarget: HTMLFormElement }) => {
    e.preventDefault();
    if (!inputMessage.trim()) return;

    const userOperationHash = await writeContractAsync({
      address: config.privateErc20Address as `0x${string}`,
      abi: privateErc20Abi,
      functionName: 'mint',
      args: [parseEther(inputMessage.trim())],
    });

    console.log('Transaction sent with hash:', userOperationHash);
  };

  const sendEmptyTx = async (e: FormEvent & { currentTarget: HTMLFormElement }) => {
    e.preventDefault();
    sendTransaction(
      {
        to: address,
        value: BigInt(0),
      },
      {
        onSuccess: (...params) => console.log(params),
        onError: (error) => console.error('Transaction failed:', error),
      },
    );

  };

  // New method 1: Prepare user operation manually
  const prepareManualMint = async () => {
    if (!walletClient || !manualMintAmount.trim()) return;

    try {
      setIsManualMintPending(true);

      // Encode the mint function call
      const mintCallData = encodeFunctionData({
        abi: privateErc20Abi,
        functionName: 'mint',
        args: [parseEther(manualMintAmount.trim())],
      });

      // Prepare the user operation using the new method
      const userOp = await walletClient.request({
        method: 'eth_prepareUserOperation',
        params: [
          [
            {
              to: config.privateErc20Address as `0x${string}`,
              data: mintCallData,
            },
          ],
          {
            // Optional: customize gas settings
            maxFeePerGas: '0x2E90EDD000', // 200 gwei in hex
            maxPriorityFeePerGas: '0x5D21DBA000', // 400 gwei in hex
          },
        ],
      } as any);

      setPreparedUserOp(userOp);
      console.log('User operation prepared:', userOp);
      setIsUserOpSigned(false); // Reset signed state when preparing new operation
    } catch (error) {
      console.error('Failed to prepare user operation:', error);
    } finally {
      setIsManualMintPending(false);
    }
  };

  // New method 2: Sign prepared user operation
  const signPreparedUserOp = async () => {
    if (!walletClient || !preparedUserOp) return;

    try {
      setIsManualMintPending(true);

      const signature = await walletClient.request({
        method: 'eth_signUserOperation',
        params: [preparedUserOp],
      } as any);

      // Add signature to the user operation
      const signedUserOp = {
        ...preparedUserOp,
        signature,
      };

      setPreparedUserOp(signedUserOp);
      console.log('User operation signed:', signature);
      setIsUserOpSigned(true); // Mark as signed
    } catch (error) {
      console.error('Failed to sign user operation:', error);
    } finally {
      setIsManualMintPending(false);
    }
  };

  // New method 3: Send signed user operation
  const sendSignedUserOp = async () => {
    if (!walletClient || !preparedUserOp || !preparedUserOp.signature) return;

    try {
      setIsManualMintPending(true);

      const receipt = await walletClient.request({
        method: 'eth_sendSignedUserOperation',
        params: [preparedUserOp],
      } as any);

      console.log('Transaction receipt:', receipt);
      setPreparedUserOp(null); // Reset after successful send
      setIsUserOpSigned(false); // Reset signed state
      setManualMintAmount(''); // Clear input
    } catch (error) {
      console.error('Failed to send signed user operation:', error);
    } finally {
      setIsManualMintPending(false);
    }
  };

  // Full workflow in one function (alternative approach)
  const manualMintFullWorkflow = async () => {
    if (!walletClient || !manualMintAmount.trim()) return;

    try {
      setIsManualMintPending(true);

      // Step 1: Prepare
      const mintCallData = encodeFunctionData({
        abi: privateErc20Abi,
        functionName: 'mint',
        args: [parseEther(manualMintAmount.trim())],
      });

      const userOp = await walletClient.request({
        method: 'eth_prepareUserOperation',
        params: [[{ to: config.privateErc20Address as `0x${string}`, data: mintCallData }]],
      } as any);

      // Step 2: Sign
      const signature = await walletClient.request({
        method: 'eth_signUserOperation',
        params: [userOp],
      } as any);

      // Step 3: Send
      const signedUserOp = { ...userOp, signature };
      const receipt = await walletClient.request({
        method: 'eth_sendSignedUserOperation',
        params: [signedUserOp],
      } as any);

      console.log('Manual mint completed:', receipt);
      setManualMintAmount('');
    } catch (error) {
      console.error('Manual mint failed:', error);
    } finally {
      setIsManualMintPending(false);
    }
  };

  const sendCall = async () => {
    const { data } = await readContract();
    if (data) setContractState(data);
  };

  // New function to read private balance using signed_eth_call
  const sendPrivateCall = async () => {
    if (!walletClient || !address) {
      console.error('Wallet not connected');
      return;
    }

    try {
      setIsPrivateBalanceFetching(true);

      const callData = encodeFunctionData({
        abi: privateErc20Abi,
        functionName: 'privateBalanceOf',
        args: [address],
      });

      console.log('callData', callData);

      const result = await walletClient.request({
        method: 'signed_eth_call',
        params: [
          {
            to: config.privateErc20Address as `0x${string}`,
            data: callData,
          },
          'latest',
        ],
      } as any);

      const decodedResult = BigInt(result as string);
      setPrivateContractState(decodedResult);
      console.log('Private balance:', decodedResult);
    } catch (error) {
      console.error('Failed to read private balance:', error);
    } finally {
      setIsPrivateBalanceFetching(false);
    }
  };

  const signMessage = async () => {
    if (!walletClient || !address) {
      console.error('Wallet not connected');
      return;
    }

    try {
      const signature = await walletClient.signMessage({
        message: messageToSign,
      } as any);
      setSignatureResult(signature as string);
      console.log('Message signed successfully:', signature);
    } catch (error) {
      console.error('Message signing failed:', error);
      setSignatureResult('Error: ' + (error as Error).message);
    }
  };

  const signTypedData = async () => {
    if (!walletClient || !address) {
      console.error('Wallet not connected');
      return;
    }

    try {
      // Example EIP-712 typed data
      const typedData = {
        domain: {
          name: 'Giano Demo',
          version: '1',
          chainId: 1,
          verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
        },
        types: {
          Message: [
            { name: 'content', type: 'string' },
            { name: 'timestamp', type: 'uint256' },
          ],
        },
        primaryType: 'Message',
        message: {
          content: 'Hello from Giano!',
          timestamp: Math.floor(Date.now() / 1000),
        },
      };

      const signature = await walletClient.request({
        method: 'eth_signTypedData_v4',
        params: [address, JSON.stringify(typedData)],
      } as any);

      setSignatureResult(signature as string);
      console.log('Typed data signed successfully:', signature);
    } catch (error) {
      console.error('Typed data signing failed:', error);
      setSignatureResult('Error: ' + (error as Error).message);
    }
  };

  // Don't render wallet-dependent UI until after hydration
  if (!mounted) {
    return (
      <div className={styles.container}>
        <Head>
          <title>Giano Demo</title>
          <meta content="Generated by @rainbow-me/create-rainbowkit" name="description" />
          <link href="/favicon.ico" rel="icon" />
        </Head>
        <main className={styles.main}>
          <div>Loading...</div>
        </main>
      </div>
    );
  }

  // Show authentication loading state
  if (isAuthenticating) {
    return (
      <div className={styles.container}>
        <Head>
          <title>Giano Demo</title>
          <meta content="Generated by @rainbow-me/create-rainbowkit" name="description" />
          <link href="/favicon.ico" rel="icon" />
        </Head>
        <main className={styles.main}>
          <div>Authenticating with passkey... Please complete the authentication prompt.</div>
        </main>
      </div>
    );
  }

  return (
    <div className={styles.container}>
      <Head>
        <title>Giano Demo</title>
        <meta content="Generated by @rainbow-me/create-rainbowkit" name="description" />
        <link href="/favicon.ico" rel="icon" />
      </Head>

      <main className={styles.main}>
        {/* EntryPoint Version Selector */}
        <div style={{
          padding: '1rem',
          border: '2px solid #3b82f6',
          borderRadius: '8px',
          marginBottom: '1rem',
          backgroundColor: '#eff6ff',
        }}>
          <h3 style={{ margin: '0 0 0.5rem 0', fontSize: '1rem', fontWeight: 'bold' }}>
            📡 Bundler EntryPoint Configuration
          </h3>
          <p style={{ margin: '0 0 1rem 0', fontSize: '0.875rem', color: '#6b7280' }}>
            This controls which EntryPoint your bundler uses to process transactions. 
            Your wallet will automatically adapt to work with the selected EntryPoint.
          </p>
          
          <EntryPointSelector
            selectedVersion={selectedEntryPointVersion}
            onVersionChange={async (version) => {
              console.log('🔧 Bundler EntryPoint Version Changed:', version);
              console.log('   Selected Version:', version);
              console.log('   Previous Version:', selectedEntryPointVersion);
              
              if (isConnected) {
                console.log('   ⚠️ Disconnecting current wallet...');
                // Disconnect first if connected since we're changing the underlying provider
                disconnect();
              }
              
              // Use the dynamic wagmi context to change EntryPoint version
              // This will automatically reconfigure wagmi with the new EntryPoint
              await setSelectedEntryPointVersion(version);
              console.log('   ✅ Bundler EntryPoint version updated to:', version);
            }}
            disabled={isAuthenticating || isReconfiguring}
          />
        </div>

        {isReconfiguring && (
          <div style={{
            padding: '1rem',
            border: '2px solid #fbbf24',
            borderRadius: '8px',
            marginBottom: '1rem',
            backgroundColor: '#fffbeb',
            textAlign: 'center',
          }}>
            <div style={{ fontSize: '1rem', fontWeight: 'bold', marginBottom: '0.5rem' }}>
              🔄 Reconfiguring for EntryPoint v{selectedEntryPointVersion}...
            </div>
            <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>
              Please wait while we set up the new EntryPoint configuration.
            </div>
          </div>
        )}

        {/* EntryPoint Verification Component */}
        <EntryPointVerification selectedVersion={selectedEntryPointVersion} />

        {/* Wallet Implementation Manager - shows current version and upgrade option */}
        {isConnected && (
          <WalletImplementationManager 
            onImplementationChange={setWalletImplementationVersion}
          />
        )}

        <div style={{ display: 'flex', gap: '10px', alignItems: 'center', marginBottom: '20px' }}>
          {isConnected ? (
            <button onClick={() => disconnect()}>Disconnect</button>
          ) : (
            <button onClick={() => connect({ connector: connectors[0] })}>Connect</button>
          )}
          
          <button 
            onClick={deletePasskey}
            style={{
              backgroundColor: '#ef4444',
              color: 'white',
              border: 'none',
              padding: '8px 16px',
              borderRadius: '4px',
              cursor: 'pointer'
            }}
          >
            Delete Passkey
          </button>
        </div>
        
        {address && (
          <div style={{ marginBottom: '20px' }}>
            <strong>Address:</strong> {address}
            <div style={{ 
              marginTop: '0.5rem', 
              fontSize: '0.875rem', 
              color: '#6b7280',
              border: '1px solid #e5e7eb',
              borderRadius: '4px',
              padding: '0.75rem',
              backgroundColor: '#f9fafb'
            }}>
              💡 <strong>New Proxy Upgrade Pattern:</strong> Your wallet always keeps the same address, 
              but you can upgrade its implementation from v0.7 to v0.8 to access new EntryPoint features.
              Use the "Wallet Implementation Status" section above to upgrade when ready.
            </div>
          </div>
        )}

        {/* Original mint method */}
        <form className={styles.formContainer} onSubmit={sendTx}>
          <input className={styles.input} type="number" placeholder="Enter amount" value={inputMessage} onChange={(e) => setInputMessage(e.target.value)} />
          <button className={styles.sendButton} disabled={!connectionReady || isWritePending || !inputMessage.trim()}>
            Mint (Standard)
          </button>
        </form>

        <form className={styles.formContainer} onSubmit={sendEmptyTx}>
          <button className={styles.sendButton} disabled={!connectionReady || isWritePending}>
            Send empty transaction
          </button>
        </form>

        {/* New manual user operation methods */}
        <div className={styles.formContainer}>
          <h3>Manual Transaction Building</h3>
          <input
            className={styles.input}
            type="number"
            placeholder="Amount to mint manually"
            value={manualMintAmount}
            onChange={(e) => setManualMintAmount(e.target.value)}
          />

          {/* Step-by-step approach */}
          <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
            <button className={styles.readButton} disabled={!connectionReady || isManualMintPending || !manualMintAmount.trim()} onClick={prepareManualMint}>
              1. Prepare UserOp
            </button>
            <button
              className={styles.readButton}
              disabled={!connectionReady || isManualMintPending || !preparedUserOp || isUserOpSigned}
              onClick={signPreparedUserOp}
            >
              2. Sign UserOp
            </button>
            <button className={styles.readButton} disabled={!connectionReady || isManualMintPending || !isUserOpSigned} onClick={sendSignedUserOp}>
              3. Send UserOp
            </button>
          </div>

          {/* Full workflow approach */}
          <button
            className={styles.sendButton}
            disabled={!connectionReady || isManualMintPending || !manualMintAmount.trim()}
            onClick={manualMintFullWorkflow}
            style={{ marginTop: '10px' }}
          >
            Mint (Manual Full Workflow)
          </button>

          {preparedUserOp && (
            <div className={styles.stateCard}>
              <p>
                <strong>UserOp Status:</strong>
              </p>
              <p>Prepared: ✅</p>
              <p>Signed: {isUserOpSigned ? '✅' : '❌'}</p>
              <p>Signature: {preparedUserOp.signature || 'None'}</p>
              <p>Nonce: {preparedUserOp.nonce}</p>
            </div>
          )}
        </div>

        <div className={styles.formContainer}>
          <button className={styles.readButton} disabled={!address || !mounted || !connectionReady || !isConnected || isReadFetching} onClick={sendCall}>
            Read balance
          </button>
          <button className={styles.readButton} disabled={!address || !mounted || !connectionReady || !isConnected || isPrivateBalanceFetching} onClick={sendPrivateCall}>
            Read Private Balance (Signed)
          </button>
        </div>

        {/* Message Signing Section */}
        <div className={styles.formContainer}>
          <input className={styles.input} type="text" placeholder="Message to sign" value={messageToSign} onChange={(e) => setMessageToSign(e.target.value)} />
          <button className={styles.readButton} disabled={!connectionReady} onClick={signMessage}>
            Sign Message (Personal)
          </button>
          <button className={styles.readButton} disabled={!connectionReady} onClick={signTypedData}>
            Sign Typed Data (EIP-712)
          </button>
        </div>

        {contractState && (
          <div className={styles.stateCard}>
            <p>
              <strong>Public Balance:</strong> {formatEther(contractState)}
            </p>
          </div>
        )}

        {privateContractState && (
          <div className={styles.stateCard}>
            <p>
              <strong>Private Balance:</strong> {formatEther(privateContractState)}
            </p>
          </div>
        )}

        {signatureResult && (
          <div className={styles.stateCard}>
            <p>
              <strong>Signature:</strong>
            </p>
            <p style={{ wordBreak: 'break-all', fontSize: '0.8em' }}>{signatureResult}</p>
          </div>
        )}

        {error && <p>Error reading balance: {error.message}</p>}
      </main>
    </div>
  );
};

export default Home;
