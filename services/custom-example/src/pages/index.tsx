import React, { type FormEvent } from 'react';
import { useEffect, useState } from 'react';
import { privateErc20Abi } from '@appliedblockchain/giano-contracts';
import type { NextPage } from 'next';
import Head from 'next/head';
import { encodeFunctionData, formatEther, parseEther } from 'viem';
import { useAccount, useConnect, useDisconnect, useReadContract, useSendTransaction, useWalletClient, useWriteContract } from 'wagmi';
import { config } from '../config';
import { gianoInjection, gianoShowListCredentialsInjection } from '../giano-injection';
import { useGiano } from '../wagmi';
import styles from '../styles/Home.module.css';

const Home: NextPage = () => {
  const [mounted, setMounted] = useState(false);
  const [connectionReady, setConnectionReady] = useState(false);
  const [isAuthenticating, setIsAuthenticating] = useState(false);
  const [showCredentialList, setShowCredentialList] = useState(false);
  const { gianoConnector, gianoProvider } = useGiano();
  const { connect } = useConnect();
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

  // Function to toggle credential list mode
  const toggleCredentialListMode = async () => {
    if (isConnected) {
      // Disconnect first if connected
      disconnect();
    }

    // Toggle the mode
    setShowCredentialList(!showCredentialList);

    if (showCredentialList) {
      gianoProvider.setInjection(gianoInjection);
    } else {
      gianoProvider.setInjection(gianoShowListCredentialsInjection);
    }

    console.log(`Switched to ${!showCredentialList ? 'credential list' : 'normal'} mode`);
  };

  // Helper function to delete passkey (clear all data including passkey)
  const deletePasskey = async () => {
    if (
      !confirm(
        '⚠️ This will permanently delete your passkey data. You will lose access to your wallet and need to create a new passkey to reconnect. Continue?',
      )
    ) {
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
      keysToRemove.forEach((key) => localStorage.removeItem(key));

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
            const response = connect({ connector: gianoConnector });
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
  }, [mounted, isConnected, connect, isAuthenticating]);

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
      const signedUserOp = { ...(userOp as object), signature } as any;
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
          <div className={styles.loadingContainer}>
            <div className={styles.spinner}></div>
            <p>Loading Giano Demo...</p>
          </div>
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
          <div className={styles.loadingContainer}>
            <div className={styles.spinner}></div>
            <p>Authenticating with passkey...</p>
            <p className={styles.subtitle}>Please complete the authentication prompt</p>
          </div>
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

      <header className={styles.header}>
        <div className={styles.headerContent}>
          <div className={styles.logo}>
            <h1>Giano Demo</h1>
            <p>Passkey-based Smart Account Wallet</p>
          </div>
          <div className={styles.walletControls}>
            {isConnected ? (
              <button onClick={() => disconnect()} className={styles.connectButton}>
                Disconnect Wallet
              </button>
            ) : (
              <button onClick={() => connect({ connector: gianoConnector })} className={styles.connectButton}>
                Connect Wallet
              </button>
            )}
            <button onClick={deletePasskey} className={styles.deleteButton}>
              Delete Passkey
            </button>
            <button onClick={toggleCredentialListMode} className={styles.toggleButton}>
              {showCredentialList ? 'Switch to Normal Mode' : 'Switch to Credential List Mode'}
            </button>
          </div>
        </div>
      </header>

      <main className={styles.main}>
        {/* Connection Status */}
        {address && (
          <div className={styles.statusCard}>
            <div className={styles.statusHeader}>
              <div className={styles.statusIndicator}></div>
              <h3>Wallet Connected</h3>
            </div>
            <p className={styles.address}>{address}</p>
            {!connectionReady && <p className={styles.statusMessage}>Initializing smart account...</p>}
          </div>
        )}

        {/* Credential Mode Status */}
        <div className={styles.section}>
          <h2 className={styles.sectionTitle}>Credential Mode</h2>
          <div className={styles.card}>
            <div className={styles.modeStatus}>
              <div className={styles.modeIndicator}>
                <span className={styles.modeLabel}>Current Mode:</span>
                <span className={`${styles.modeValue} ${showCredentialList ? styles.credentialListMode : styles.normalMode}`}>
                  {showCredentialList ? 'Credential List Mode' : 'Normal Mode'}
                </span>
              </div>
              <div className={styles.modeDescription}>
                <p>
                  <strong>Normal Mode:</strong> Automatically selects credentials from storage
                </p>
                <p>
                  <strong>Credential List Mode:</strong> Shows a list of available credentials for user selection
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Quick Actions */}
        <div className={styles.section}>
          <h2 className={styles.sectionTitle}>Quick Actions</h2>
          <div className={styles.cardGrid}>
            <div className={styles.card}>
              <h3>Standard Mint</h3>
              <p>Mint tokens using the standard contract interaction</p>
              <form onSubmit={sendTx} className={styles.form}>
                <input
                  className={styles.input}
                  type="number"
                  placeholder="Enter amount"
                  value={inputMessage}
                  onChange={(e) => setInputMessage(e.target.value)}
                />
                <button className={styles.primaryButton} disabled={!connectionReady || isWritePending || !inputMessage.trim()}>
                  {isWritePending ? 'Minting...' : 'Mint Tokens'}
                </button>
              </form>
            </div>

            <div className={styles.card}>
              <h3>Empty Transaction</h3>
              <p>Send an empty transaction to test the wallet</p>
              <form onSubmit={sendEmptyTx} className={styles.form}>
                <button className={styles.secondaryButton} disabled={!connectionReady || isWritePending}>
                  Send Empty Tx
                </button>
              </form>
            </div>
          </div>
        </div>

        {/* Manual Transaction Building */}
        <div className={styles.section}>
          <h2 className={styles.sectionTitle}>Advanced: Manual Transaction Building</h2>
          <div className={styles.card}>
            <h3>Step-by-Step User Operation</h3>
            <p>Build and execute transactions manually using the three-step process</p>

            <div className={styles.form}>
              <input
                className={styles.input}
                type="number"
                placeholder="Amount to mint manually"
                value={manualMintAmount}
                onChange={(e) => setManualMintAmount(e.target.value)}
              />
            </div>

            <div className={styles.stepButtons}>
              <button className={styles.stepButton} disabled={!connectionReady || isManualMintPending || !manualMintAmount.trim()} onClick={prepareManualMint}>
                <span className={styles.stepNumber}>1</span>
                Prepare UserOp
              </button>
              <button
                className={styles.stepButton}
                disabled={!connectionReady || isManualMintPending || !preparedUserOp || isUserOpSigned}
                onClick={signPreparedUserOp}
              >
                <span className={styles.stepNumber}>2</span>
                Sign UserOp
              </button>
              <button className={styles.stepButton} disabled={!connectionReady || isManualMintPending || !isUserOpSigned} onClick={sendSignedUserOp}>
                <span className={styles.stepNumber}>3</span>
                Send UserOp
              </button>
            </div>

            <div className={styles.divider}>
              <span>OR</span>
            </div>

            <button
              className={styles.primaryButton}
              disabled={!connectionReady || isManualMintPending || !manualMintAmount.trim()}
              onClick={manualMintFullWorkflow}
            >
              {isManualMintPending ? 'Processing...' : 'Mint (Full Workflow)'}
            </button>

            {preparedUserOp && (
              <div className={styles.statusCard}>
                <h4>User Operation Status</h4>
                <div className={styles.statusGrid}>
                  <div className={styles.statusItem}>
                    <span className={styles.statusLabel}>Prepared:</span>
                    <span className={styles.statusValue}>✅</span>
                  </div>
                  <div className={styles.statusItem}>
                    <span className={styles.statusLabel}>Signed:</span>
                    <span className={styles.statusValue}>{isUserOpSigned ? '✅' : '❌'}</span>
                  </div>
                  <div className={styles.statusItem}>
                    <span className={styles.statusLabel}>Nonce:</span>
                    <span className={styles.statusValue}>{preparedUserOp.nonce}</span>
                  </div>
                  {preparedUserOp.signature && (
                    <div className={styles.statusItem}>
                      <span className={styles.statusLabel}>Signature:</span>
                      <span className={styles.statusValue}>{preparedUserOp.signature.slice(0, 20)}...</span>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Balance Reading */}
        <div className={styles.section}>
          <h2 className={styles.sectionTitle}>Balance & Data Reading</h2>
          <div className={styles.cardGrid}>
            <div className={styles.card}>
              <h3>Public Balance</h3>
              <p>Read your public token balance</p>
              <button
                className={styles.secondaryButton}
                disabled={!address || !mounted || !connectionReady || !isConnected || isReadFetching}
                onClick={sendCall}
              >
                {isReadFetching ? 'Reading...' : 'Read Balance'}
              </button>
              {contractState && (
                <div className={styles.resultCard}>
                  <strong>Balance:</strong> {formatEther(contractState)} tokens
                </div>
              )}
            </div>

            <div className={styles.card}>
              <h3>Private Balance</h3>
              <p>Read your private balance using signed calls</p>
              <button
                className={styles.secondaryButton}
                disabled={!address || !mounted || !connectionReady || !isConnected || isPrivateBalanceFetching}
                onClick={sendPrivateCall}
              >
                {isPrivateBalanceFetching ? 'Reading...' : 'Read Private Balance'}
              </button>
              {privateContractState && (
                <div className={styles.resultCard}>
                  <strong>Private Balance:</strong> {formatEther(privateContractState)} tokens
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Message Signing */}
        <div className={styles.section}>
          <h2 className={styles.sectionTitle}>Message Signing</h2>
          <div className={styles.card}>
            <h3>Sign Messages</h3>
            <p>Test message signing capabilities</p>

            <div className={styles.form}>
              <input
                className={styles.input}
                type="text"
                placeholder="Message to sign"
                value={messageToSign}
                onChange={(e) => setMessageToSign(e.target.value)}
              />
            </div>

            <div className={styles.buttonGroup}>
              <button className={styles.secondaryButton} disabled={!connectionReady} onClick={signMessage}>
                Sign Message (Personal)
              </button>
              <button className={styles.secondaryButton} disabled={!connectionReady} onClick={signTypedData}>
                Sign Typed Data (EIP-712)
              </button>
            </div>

            {signatureResult && (
              <div className={styles.resultCard}>
                <h4>Signature Result</h4>
                <code className={styles.signatureCode}>{signatureResult}</code>
              </div>
            )}
          </div>
        </div>

        {/* Error Display */}
        {error && (
          <div className={styles.errorCard}>
            <h3>Error</h3>
            <p>{error.message}</p>
          </div>
        )}
      </main>
    </div>
  );
};

export default Home;
