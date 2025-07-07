import React, { type FormEvent } from 'react';
import { useEffect, useState } from 'react';
import { privateErc20Abi } from '@appliedblockchain/giano-contracts';
import type { NextPage } from 'next';
import Head from 'next/head';
import { formatEther, parseEther } from 'viem';
import { encodeFunctionData } from 'viem';
import { useAccount, useConnect, useDisconnect, useReadContract, useSendTransaction, useWalletClient, useWriteContract } from 'wagmi';
import { config } from '../config';
import { getBundler, gianoConnector } from '../wagmi';
import styles from '../styles/Home.module.css';

const Home: NextPage = () => {
  const [mounted, setMounted] = useState(false);
  const [connectionReady, setConnectionReady] = useState(false);
  const [isAuthenticating, setIsAuthenticating] = useState(false);
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
    address: config.privateErc20Address,
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
  const [signatureResult, setSignatureResult] = useState<string>('');
  const [messageToSign, setMessageToSign] = useState('Hello, please sign this message!');
  const [isManualMintPending, setIsManualMintPending] = useState(false);
  const [preparedUserOp, setPreparedUserOp] = useState<any>(null);
  const [isUserOpSigned, setIsUserOpSigned] = useState(false);

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
      address: config.privateErc20Address,
      abi: privateErc20Abi,
      functionName: 'mint',
      args: [parseEther(inputMessage.trim())],
    });

    const userOpReceipt = await getBundler().waitForUserOperationReceipt({ hash: userOperationHash });
    console.log('✅ Transaction receipt received:', userOpReceipt.receipt);
  };

  const sendEmptyTx = async (e: FormEvent & { currentTarget: HTMLFormElement }) => {
    e.preventDefault();
    sendTransaction(
      {
        to: address,
        value: 0n,
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
              to: config.privateErc20Address,
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
      console.log('UserOp signature:', userOp?.signature);
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
        params: [[{ to: config.privateErc20Address, data: mintCallData }]],
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
        {isConnected ? (
          <button onClick={() => disconnect()}>Disconnect</button>
        ) : (
          <button onClick={() => connect({ connector: gianoConnector })}>Connect</button>
        )}
        {address}

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
              <strong>Balance:</strong> {formatEther(contractState)}
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
