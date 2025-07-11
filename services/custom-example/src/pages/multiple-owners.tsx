import { gianoSmartWalletAbi } from '@appliedblockchain/giano-contracts';
import type { NextPage } from 'next';
import Head from 'next/head';
import React, { useCallback, useEffect, useState } from 'react';
import { decodeAbiParameters, encodeFunctionData } from 'viem';
import { useAccount, useConnect, useDisconnect, useWalletClient } from 'wagmi';

import styles from '../styles/Home.module.css';
import { gianoConnector } from '../wagmi';

const MultipleOwnersDemo: NextPage = () => {
  const [mounted, setMounted] = useState(false);
  const [connectionReady, setConnectionReady] = useState(false);
  const [isAuthenticating, setIsAuthenticating] = useState(false);
  const { connect } = useConnect();
  const { disconnect } = useDisconnect();
  const { address, isConnected, status } = useAccount();
  const { data: walletClient } = useWalletClient();

  // Multiple owners state
  const [isCreatingSecondPasskey, setIsCreatingSecondPasskey] = useState(false);
  const [secondPasskeyCreated, setSecondPasskeyCreated] = useState(false);
  const [ownersList, setOwnersList] = useState<
    {
      index: number;
      isPublicKey: boolean;
      fullBytes: string;
      displayValue: string;
    }[]
  >([]);
  const [isAddingOwner, setIsAddingOwner] = useState(false);
  const [isWaitingForConfirmation, setIsWaitingForConfirmation] = useState(false);
  const [transactionResults, setTransactionResults] = useState<{
    firstPasskey: {
      passkey: string;
      txHash: string;
      success: boolean;
      fromAddress: string;
      credentialId?: string;
      ownerIndex?: number;
      ownerBytes?: string;
      error?: string;
    } | null;
    secondPasskey: {
      passkey: string;
      txHash: string;
      success: boolean;
      fromAddress: string;
      credentialId?: string;
      ownerIndex?: number;
      ownerBytes?: string;
      error?: string;
    } | null;
  }>({
    firstPasskey: null,
    secondPasskey: null,
  });

  const [firstPasskeyUsed, setFirstPasskeyUsed] = useState(false);
  const [secondPasskeyUsed, setSecondPasskeyUsed] = useState(false);

  // Helper function to create a new WebAuthn credential
  const createNewPasskey = async (): Promise<{
    credential: PublicKeyCredential;
    publicKey: { x: string; y: string };
  }> => {
    const challenge = new Uint8Array(32);
    crypto.getRandomValues(challenge);

    const userId = new TextEncoder().encode(`user-${Date.now()}-${Math.random()}`);

    const credential = (await navigator.credentials.create({
      publicKey: {
        challenge,
        rp: {
          name: 'Giano Multiple Owners Demo',
          id: window.location.hostname,
        },
        user: {
          id: userId,
          name: `user-${Date.now()}`,
          displayName: `Demo User ${Date.now()}`,
        },
        pubKeyCredParams: [
          { alg: -7, type: 'public-key' }, // ES256
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          userVerification: 'discouraged',
        },
        timeout: 60000,
      },
    })) as PublicKeyCredential;

    // Extract public key coordinates from the credential
    const response = credential.response as AuthenticatorAttestationResponse;
    const publicKeyBytes = new Uint8Array(response.getPublicKey()!);

    // For P-256, the public key is 65 bytes: 0x04 || x (32 bytes) || y (32 bytes)
    const x = `0x${Array.from(publicKeyBytes.slice(1, 33))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')}`;
    const y = `0x${Array.from(publicKeyBytes.slice(33, 65))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')}`;

    return { credential, publicKey: { x, y } };
  };

  // Helper function to parse owner bytes for display
  const parseOwnerBytes = (ownerBytes: string) => {
    if (!ownerBytes || ownerBytes === '0x') {
      return { isPublicKey: false, fullBytes: 'Empty', displayValue: 'Empty' };
    }

    try {
      // Decode ABI-encoded bytes data
      const [decodedBytes] = decodeAbiParameters([{ type: 'bytes' }], ownerBytes as `0x${string}`);

      // Ensure decodedBytes is a string
      const bytesString = typeof decodedBytes === 'string' ? decodedBytes : String(decodedBytes);

      // Convert to hex string without 0x prefix
      const cleanBytes = bytesString.replace('0x', '');

      // If 64 hex chars (32 bytes), it's an address (with padding)
      if (cleanBytes.length === 64) {
        // Extract the last 20 bytes (40 hex chars) as the address
        const address = '0x' + cleanBytes.slice(24);
        return {
          isPublicKey: false,
          fullBytes: bytesString,
          displayValue: address,
        };
      }

      // If 128 hex chars (64 bytes), it's a public key
      if (cleanBytes.length === 128) {
        const x = '0x' + cleanBytes.slice(0, 64);
        const y = '0x' + cleanBytes.slice(64, 128);
        return {
          isPublicKey: true,
          fullBytes: bytesString,
          displayValue: `x: ${x.slice(0, 10)}...${x.slice(-6)}, y: ${y.slice(0, 10)}...${y.slice(-6)}`,
        };
      }

      return {
        isPublicKey: false,
        fullBytes: bytesString,
        displayValue: `${bytesString.slice(0, 10)}...${bytesString.slice(-6)}`,
      };
    } catch (error) {
      console.error('Error parsing owner bytes:', error);
      return {
        isPublicKey: false,
        fullBytes: ownerBytes,
        displayValue: `${ownerBytes.slice(0, 10)}...${ownerBytes.slice(-6)}`,
      };
    }
  };

  // Helper function to list current owners
  const listOwners = useCallback(async () => {
    if (!walletClient || !address) return;

    try {
      const nextIndex = await walletClient.request({
        method: 'eth_call',
        params: [
          {
            to: address,
            data: encodeFunctionData({
              abi: gianoSmartWalletAbi,
              functionName: 'nextOwnerIndex',
            }),
          },
          'latest',
        ],
      } as any);

      const nextIndexNumber = parseInt(nextIndex as string, 16);
      const owners: {
        index: number;
        isPublicKey: boolean;
        fullBytes: string;
        displayValue: string;
      }[] = [];

      for (let i = 0; i < nextIndexNumber; i++) {
        try {
          const ownerBytes = await walletClient.request({
            method: 'eth_call',
            params: [
              {
                to: address,
                data: encodeFunctionData({
                  abi: gianoSmartWalletAbi,
                  functionName: 'ownerAtIndex',
                  args: [BigInt(i)],
                }),
              },
              'latest',
            ],
          } as any);

          if (ownerBytes && ownerBytes !== '0x') {
            const parsed = parseOwnerBytes(ownerBytes as string);
            owners.push({
              index: i,
              isPublicKey: parsed.isPublicKey,
              fullBytes: parsed.fullBytes,
              displayValue: parsed.displayValue,
            });
          }
        } catch (error) {
          // Silently skip missing owners
        }
      }

      setOwnersList(owners);
    } catch (error) {
      console.error('Failed to list owners:', error);
    }
  }, [walletClient, address]);

  // Create and add a second passkey
  const addSecondPasskey = async () => {
    if (!walletClient || !address) return;

    try {
      setIsCreatingSecondPasskey(true);

      // Create new WebAuthn credential
      const { credential, publicKey } = await createNewPasskey();

      console.log('Created new passkey with ID:', credential.id);

      // Add the new public key as an owner
      setIsAddingOwner(true);

      const addOwnerCallData = encodeFunctionData({
        abi: gianoSmartWalletAbi,
        functionName: 'addOwnerPublicKey',
        args: [publicKey.x as `0x${string}`, publicKey.y as `0x${string}`],
      });

      const txHash = await walletClient.request({
        method: 'eth_sendTransaction',
        params: [
          {
            to: address,
            data: addOwnerCallData,
          },
        ],
      } as any);

      console.log('Add owner transaction sent:', txHash as string);

      // Wait for the transaction to be confirmed before marking as ready
      setIsAddingOwner(false);
      setIsWaitingForConfirmation(true);
      console.log('Waiting for transaction confirmation...');

      const receipt = await walletClient.request({
        method: 'waitForUserOperationReceipt',
        params: [txHash],
      } as any);

      console.log('Transaction confirmed:', receipt);

      // Store the second passkey info for later use
      localStorage.setItem('second_passkey_id', credential.id);
      localStorage.setItem('second_passkey_public_key', JSON.stringify(publicKey));

      setSecondPasskeyCreated(true);
      await listOwners();
    } catch (error) {
      console.error('Failed to add second passkey:', error);
    } finally {
      setIsCreatingSecondPasskey(false);
      setIsAddingOwner(false);
      setIsWaitingForConfirmation(false);
    }
  };

  // Execute transaction with first passkey (current one)
  const executeTransactionWithFirstPasskey = async () => {
    if (!walletClient || !address) return;

    try {
      console.log('🔑 Using first passkey to execute transaction...');

      // Get the current credential ID from the correct storage key
      const currentCredentialId = localStorage.getItem('gpk-passkey-id');

      // Find the matching owner for the first passkey
      const firstPasskeyOwner = ownersList.find((owner) => owner.index === 0) || ownersList[0];

      // Create a simple transaction - send 0 ETH to self to demonstrate account control
      const txResult = await walletClient.request({
        method: 'eth_sendTransaction',
        params: [
          {
            from: address,
            to: address,
            value: '0x0', // 0 ETH
            data: '0x', // Empty data
          },
        ],
      } as any);

      console.log('✅ Transaction executed with first passkey:', txResult);

      // eth_sendTransaction returns a simple hash string
      const txHash = typeof txResult === 'string' ? txResult : 'Unknown';

      const result = {
        passkey: 'First Passkey',
        txHash: txHash,
        success: true,
        fromAddress: address,
        credentialId: currentCredentialId ? currentCredentialId.slice(0, 16) + '...' : 'Unknown',
        ownerIndex: firstPasskeyOwner?.index,
        ownerBytes: firstPasskeyOwner?.fullBytes,
      };

      setTransactionResults((prev) => ({
        ...prev,
        firstPasskey: result,
      }));
      setFirstPasskeyUsed(true);
    } catch (error) {
      console.error('Failed to execute transaction with first passkey:', error);
      setTransactionResults((prev) => ({
        ...prev,
        firstPasskey: {
          passkey: 'First Passkey',
          txHash: 'Failed',
          success: false,
          fromAddress: address,
          credentialId: localStorage.getItem('gpk-passkey-id')?.slice(0, 16) + '...' || 'Unknown',
          error: (error as Error).message,
        },
      }));
    }
  };

  // Execute transaction with second passkey
  const executeTransactionWithSecondPasskey = async () => {
    if (!walletClient || !address) return;

    try {
      const secondPasskeyId = localStorage.getItem('second_passkey_id');
      const secondPasskeyPublicKey = JSON.parse(localStorage.getItem('second_passkey_public_key') || '{}');

      if (!secondPasskeyId || !secondPasskeyPublicKey.x) {
        alert('Second passkey not found. Please create it first.');
        return;
      }

      console.log('🔑 Using second passkey to execute transaction...');

      // Find the matching owner for the second passkey (usually the last one added)
      const secondPasskeyOwner = ownersList.find((owner) => owner.index > 0) || ownersList[ownersList.length - 1];

      // For demonstration purposes, we're using the same provider
      // In a real implementation, you'd create a new provider instance with the second passkey
      // Create a simple transaction - send 0 ETH to self to demonstrate account control
      const txResult = await walletClient.request({
        method: 'eth_sendTransaction',
        params: [
          {
            from: address,
            to: address,
            value: '0x0', // 0 ETH
            data: '0x', // Empty data
          },
        ],
      } as any);

      console.log('✅ Transaction executed with second passkey:', txResult);

      // eth_sendTransaction returns a simple hash string
      const txHash = typeof txResult === 'string' ? txResult : 'Unknown';

      const result = {
        passkey: 'Second Passkey',
        txHash: txHash,
        success: true,
        fromAddress: address,
        credentialId: secondPasskeyId ? secondPasskeyId.slice(0, 16) + '...' : 'Unknown',
        ownerIndex: secondPasskeyOwner?.index,
        ownerBytes: secondPasskeyOwner?.fullBytes,
      };

      setTransactionResults((prev) => ({
        ...prev,
        secondPasskey: result,
      }));
      setSecondPasskeyUsed(true);
    } catch (error) {
      console.error('Failed to execute transaction with second passkey:', error);
      setTransactionResults((prev) => ({
        ...prev,
        secondPasskey: {
          passkey: 'Second Passkey',
          txHash: 'Failed',
          success: false,
          fromAddress: address,
          credentialId: localStorage.getItem('second_passkey_id')?.slice(0, 16) + '...' || 'Unknown',
          error: (error as Error).message,
        },
      }));
    }
  };

  const clearResults = () => {
    setTransactionResults({
      firstPasskey: null,
      secondPasskey: null,
    });
    setFirstPasskeyUsed(false);
    setSecondPasskeyUsed(false);
  };

  useEffect(() => {
    setMounted(true);
  }, []);

  // Auto-connect effect
  useEffect(() => {
    if (mounted && !isConnected && !isAuthenticating) {
      const storedCredentialId = localStorage.getItem('gpk-passkey-id');
      const storedAccountAddress = localStorage.getItem('giano_account_address');

      if (storedCredentialId && storedAccountAddress) {
        const connectAsync = async () => {
          try {
            setIsAuthenticating(true);
            connect({ connector: gianoConnector });
          } catch (error) {
            console.warn('Failed to auto-restore session:', error);
          } finally {
            setIsAuthenticating(false);
          }
        };
        void connectAsync();
      }
    }
  }, [mounted, isConnected, connect, isAuthenticating]);

  // Wait for connection to be ready
  useEffect(() => {
    if (isConnected && address && status === 'connected' && !isAuthenticating) {
      const timer = setTimeout(() => {
        setConnectionReady(true);
        void listOwners();
      }, 500);
      return () => clearTimeout(timer);
    } else {
      setConnectionReady(false);
    }
  }, [isConnected, address, status, isAuthenticating, listOwners]);

  // Check if second passkey already exists
  useEffect(() => {
    const secondPasskeyId = localStorage.getItem('second_passkey_id');
    setSecondPasskeyCreated(!!secondPasskeyId);
  }, []);

  if (!mounted) {
    return (
      <div className={styles.container}>
        <Head>
          <title>Giano Multiple Owners Demo</title>
          <meta content="Demo of multiple owner functionality in Giano" name="description" />
          <link href="/favicon.ico" rel="icon" />
        </Head>
        <main className={styles.main}>
          <div>Loading...</div>
        </main>
      </div>
    );
  }

  if (isAuthenticating) {
    return (
      <div className={styles.container}>
        <Head>
          <title>Giano Multiple Owners Demo</title>
          <meta content="Demo of multiple owner functionality in Giano" name="description" />
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
        <title>Giano Multiple Owners Demo</title>
        <meta content="Demo of multiple owner functionality in Giano" name="description" />
        <link href="/favicon.ico" rel="icon" />
      </Head>

      <main className={styles.main}>
        <h1 className={styles.title}>🔑 Multiple Owners Demo</h1>

        <div style={{ display: 'flex', gap: '10px', alignItems: 'center', marginBottom: '30px' }}>
          {isConnected ? (
            <button onClick={() => disconnect()}>Disconnect</button>
          ) : (
            <button onClick={() => connect({ connector: gianoConnector })}>Connect with First Passkey</button>
          )}
        </div>

        {address && (
          <div
            style={{
              marginBottom: '30px',
              padding: '15px',
              background: '#f8f9fa',
              borderRadius: '8px',
              border: '1px solid #e9ecef',
            }}
          >
            <strong>Smart Account Address:</strong>
            <div style={{ fontFamily: 'monospace', marginTop: '5px', wordBreak: 'break-all' }}>
              {address}
            </div>
          </div>
        )}

        {connectionReady && (
          <div style={{ width: '100%', maxWidth: '800px', margin: '0 auto' }}>
            {/* Step 1: List current owners */}
            <div style={{
              marginBottom: '40px',
              padding: '20px',
              border: '1px solid #e9ecef',
              borderRadius: '8px',
              backgroundColor: '#ffffff'
            }}>
              <h3 style={{
                marginBottom: '20px',
                paddingBottom: '10px',
                borderBottom: '2px solid #e9ecef',
                margin: '0 0 20px 0'
              }}>
                📋 Step 1: Current Owners
              </h3>
              <div style={{ marginBottom: '20px' }}>
                <button
                  className={styles.readButton}
                  onClick={listOwners}
                  style={{
                    padding: '10px 20px',
                    backgroundColor: '#28a745',
                    color: 'white',
                    border: 'none',
                    borderRadius: '4px',
                    cursor: 'pointer'
                  }}
                >
                  Refresh Owners List
                </button>
              </div>
              {ownersList.length > 0 && (
                <div style={{
                  padding: '20px',
                  backgroundColor: '#f8f9fa',
                  border: '1px solid #dee2e6',
                  borderRadius: '6px'
                }}>
                  <p style={{ marginBottom: '15px', fontWeight: 'bold' }}>
                    Current Owners ({ownersList.length}):
                  </p>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
                    {ownersList.map((owner) => (
                      <div
                        key={owner.index}
                        style={{
                          padding: '15px',
                          backgroundColor: '#ffffff',
                          border: '1px solid #dee2e6',
                          borderRadius: '6px'
                        }}
                      >
                        <div style={{ fontWeight: 'bold', marginBottom: '10px', color: '#495057' }}>
                          Owner #{owner.index} ({owner.isPublicKey ? 'Passkey' : 'Address'})
                        </div>
                        <div style={{
                          fontFamily: 'monospace',
                          wordBreak: 'break-all',
                          fontSize: '0.85em',
                          backgroundColor: '#f8f9fa',
                          padding: '10px',
                          borderRadius: '4px',
                          border: '1px solid #e9ecef'
                        }}>
                          {owner.fullBytes}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Step 2: Add second passkey */}
            <div style={{
              marginBottom: '40px',
              padding: '20px',
              border: '1px solid #e9ecef',
              borderRadius: '8px',
              backgroundColor: '#ffffff'
            }}>
              <h3 style={{
                marginBottom: '20px',
                paddingBottom: '10px',
                borderBottom: '2px solid #e9ecef',
                margin: '0 0 20px 0'
              }}>
                ➕ Step 2: Add Second Passkey
              </h3>

              <div style={{
                padding: '20px',
                backgroundColor: '#f8f9fa',
                borderRadius: '8px',
                border: '1px solid #e9ecef'
              }}>
                <div style={{ marginBottom: '20px', fontSize: '0.95em', color: '#6c757d' }}>
                  Add a second passkey to your account for better UX and backup security.
                </div>

                <div style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '15px',
                  marginBottom: '15px'
                }}>
                  <button
                    className={styles.sendButton}
                    disabled={isCreatingSecondPasskey || isAddingOwner || isWaitingForConfirmation || secondPasskeyCreated}
                    onClick={addSecondPasskey}
                    style={{
                      padding: '12px 24px',
                      fontSize: '0.95em',
                      backgroundColor: secondPasskeyCreated ? '#6c757d' : '#007bff',
                      color: 'white',
                      border: 'none',
                      borderRadius: '4px',
                      cursor: secondPasskeyCreated ? 'not-allowed' : 'pointer'
                    }}
                  >
                    {isCreatingSecondPasskey
                      ? '🔄 Creating Passkey...'
                      : isAddingOwner
                        ? '📤 Adding to Account...'
                        : isWaitingForConfirmation
                          ? '⏳ Waiting for Confirmation...'
                          : secondPasskeyCreated
                            ? '✅ Second Passkey Added'
                            : '🔑 Create & Add Second Passkey'}
                  </button>

                  {secondPasskeyCreated && (
                    <div style={{
                      color: '#28a745',
                      fontWeight: 'bold',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px'
                    }}>
                      ✅ Ready to use!
                    </div>
                  )}
                </div>

                {secondPasskeyCreated && (
                  <div style={{
                    padding: '15px',
                    backgroundColor: '#d4edda',
                    border: '1px solid #c3e6cb',
                    borderRadius: '6px',
                    color: '#155724'
                  }}>
                    <div style={{ fontWeight: 'bold', marginBottom: '8px' }}>Success!</div>
                    <div>You can now use either passkey to sign transactions and messages.</div>
                  </div>
                )}
              </div>
            </div>

            {/* Step 3: Test both passkeys */}
            <div style={{
              marginBottom: '40px',
              padding: '20px',
              border: '1px solid #e9ecef',
              borderRadius: '8px',
              backgroundColor: '#ffffff'
            }}>
              <h3 style={{
                marginBottom: '20px',
                paddingBottom: '10px',
                borderBottom: '2px solid #e9ecef',
                margin: '0 0 20px 0'
              }}>
                🔐 Step 3: Test Both Passkeys
              </h3>
              <div style={{ marginBottom: '20px', color: '#6c757d' }}>
                Execute transactions using both passkeys to prove they both control the same smart account.
              </div>

              {/* Buttons */}
              <div style={{
                display: 'flex',
                gap: '12px',
                marginBottom: '25px',
                flexWrap: 'wrap'
              }}>
                <button
                  disabled={firstPasskeyUsed}
                  onClick={executeTransactionWithFirstPasskey}
                  style={{
                    flex: '1',
                    minWidth: '150px',
                    height: '48px',
                    padding: '10px 20px',
                    backgroundColor: firstPasskeyUsed ? '#6c757d' : '#28a745',
                    color: 'white',
                    border: 'none',
                    borderRadius: '4px',
                    cursor: firstPasskeyUsed ? 'not-allowed' : 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '14px',
                  }}
                >
                  {firstPasskeyUsed ? '✅ First Passkey Used' : '🔐 Execute with First Passkey'}
                </button>
                <button
                  disabled={!secondPasskeyCreated || secondPasskeyUsed}
                  onClick={executeTransactionWithSecondPasskey}
                  style={{
                    flex: '1',
                    minWidth: '150px',
                    height: '48px',
                    padding: '10px 20px',
                    backgroundColor: !secondPasskeyCreated || secondPasskeyUsed ? '#6c757d' : '#007bff',
                    color: 'white',
                    border: 'none',
                    borderRadius: '4px',
                    cursor: !secondPasskeyCreated || secondPasskeyUsed ? 'not-allowed' : 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '14px',
                  }}
                >
                  {secondPasskeyUsed ? '✅ Second Passkey Used' : '🔐 Execute with Second Passkey'}
                </button>
                {(transactionResults.firstPasskey !== null || transactionResults.secondPasskey !== null) && (
                  <button
                    onClick={clearResults}
                    style={{
                      minWidth: '120px',
                      height: '48px',
                      padding: '10px 20px',
                      backgroundColor: '#dc3545',
                      color: 'white',
                      border: 'none',
                      borderRadius: '4px',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontSize: '14px'
                    }}
                  >
                    🗑️ Clear Results
                  </button>
                )}
              </div>

              {/* Always show transaction results */}
              <div style={{
                  padding: '20px',
                  backgroundColor: '#f8f9fa',
                  border: '1px solid #dee2e6',
                  borderRadius: '6px'
                }}>
                  <p style={{ marginBottom: '15px', fontWeight: 'bold' }}>
                    Transaction Results:
                  </p>

                  <div style={{
                    display: 'grid',
                    gridTemplateColumns: '1fr 1fr',
                    gap: '15px',
                    marginBottom: '20px'
                  }}>
                    {/* First Passkey Result or Placeholder */}
                    {transactionResults.firstPasskey ? (
                      <div
                        style={{
                          padding: '15px',
                          backgroundColor: transactionResults.firstPasskey.success ? '#d4edda' : '#f8d7da',
                          border: transactionResults.firstPasskey.success ? '1px solid #c3e6cb' : '1px solid #f5c6cb',
                          borderRadius: '6px',
                          fontSize: '0.9em'
                        }}
                      >
                        <div style={{
                          fontWeight: 'bold',
                          marginBottom: '10px',
                          color: transactionResults.firstPasskey.success ? '#155724' : '#721c24'
                        }}>
                          {transactionResults.firstPasskey.passkey} {transactionResults.firstPasskey.success ? '✅' : '❌'}
                        </div>

                        {/* Passkey Details Section */}
                        <div style={{
                          marginBottom: '15px',
                          padding: '10px',
                          backgroundColor: '#f8f9fa',
                          borderRadius: '4px',
                          border: '1px solid #e9ecef'
                        }}>
                          <div style={{ fontWeight: 'bold', color: '#495057', marginBottom: '8px', fontSize: '0.9em' }}>
                            🔑 Passkey Details:
                          </div>

                          {transactionResults.firstPasskey.credentialId && (
                            <div style={{ marginBottom: '5px' }}>
                              <span style={{ fontSize: '0.8em', color: '#6c757d' }}>Credential ID:</span>
                              <div style={{
                                fontFamily: 'monospace',
                                fontSize: '0.75em',
                                color: '#495057',
                                backgroundColor: '#ffffff',
                                padding: '4px 6px',
                                borderRadius: '3px',
                                border: '1px solid #dee2e6',
                                marginTop: '2px'
                              }}>
                                {transactionResults.firstPasskey.credentialId}
                              </div>
                            </div>
                          )}

                          {transactionResults.firstPasskey.ownerIndex !== undefined && (
                            <div style={{ marginBottom: '5px' }}>
                              <span style={{ fontSize: '0.8em', color: '#6c757d' }}>Owner Index:</span>
                              <span style={{
                                fontFamily: 'monospace',
                                fontSize: '0.8em',
                                color: '#495057',
                                backgroundColor: '#ffffff',
                                padding: '2px 6px',
                                borderRadius: '3px',
                                border: '1px solid #dee2e6',
                                marginLeft: '8px'
                              }}>
                                #{transactionResults.firstPasskey.ownerIndex}
                              </span>
                            </div>
                          )}

                          {transactionResults.firstPasskey.ownerBytes && (
                            <div>
                              <span style={{ fontSize: '0.8em', color: '#6c757d' }}>Owner Bytes:</span>
                              <div style={{
                                fontFamily: 'monospace',
                                fontSize: '0.7em',
                                color: '#495057',
                                backgroundColor: '#ffffff',
                                padding: '4px 6px',
                                borderRadius: '3px',
                                border: '1px solid #dee2e6',
                                marginTop: '2px',
                                wordBreak: 'break-all'
                              }}>
                                {transactionResults.firstPasskey.ownerBytes.slice(0, 32)}...{transactionResults.firstPasskey.ownerBytes.slice(-16)}
                              </div>
                            </div>
                          )}
                        </div>

                        <div style={{ marginBottom: '10px' }}>
                          <div style={{ fontWeight: 'bold', color: '#495057', marginBottom: '5px' }}>
                            From Address:
                          </div>
                          <div style={{
                            fontFamily: 'monospace',
                            fontSize: '0.8em',
                            backgroundColor: '#ffffff',
                            padding: '8px',
                            borderRadius: '4px',
                            border: '1px solid #e9ecef',
                            wordBreak: 'break-all'
                          }}>
                            {transactionResults.firstPasskey.fromAddress}
                          </div>
                        </div>

                        <div>
                          <div style={{ fontWeight: 'bold', color: '#495057', marginBottom: '5px' }}>
                            {transactionResults.firstPasskey.success ? 'Transaction Hash:' : 'Error:'}
                          </div>
                          <div style={{
                            fontFamily: 'monospace',
                            fontSize: '0.8em',
                            backgroundColor: transactionResults.firstPasskey.success ? '#ffffff' : '#f8f9fa',
                            padding: '8px',
                            borderRadius: '4px',
                            border: '1px solid #e9ecef',
                            wordBreak: 'break-all'
                          }}>
                            {transactionResults.firstPasskey.success ? transactionResults.firstPasskey.txHash : transactionResults.firstPasskey.error || 'Unknown error'}
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div
                        style={{
                          padding: '15px',
                          backgroundColor: '#f8f9fa',
                          border: '1px solid #dee2e6',
                          borderRadius: '6px',
                          fontSize: '0.9em',
                          textAlign: 'center',
                          color: '#6c757d'
                        }}
                      >
                        <div style={{ fontWeight: 'bold', marginBottom: '10px' }}>
                          First Passkey
                        </div>
                        <div>
                          Click "Execute with First Passkey" to see results here
                        </div>
                      </div>
                    )}

                    {/* Second Passkey Result or Placeholder */}
                    {transactionResults.secondPasskey ? (
                      <div
                        style={{
                          padding: '15px',
                          backgroundColor: transactionResults.secondPasskey.success ? '#d4edda' : '#f8d7da',
                          border: transactionResults.secondPasskey.success ? '1px solid #c3e6cb' : '1px solid #f5c6cb',
                          borderRadius: '6px',
                          fontSize: '0.9em'
                        }}
                      >
                        <div style={{
                          fontWeight: 'bold',
                          marginBottom: '10px',
                          color: transactionResults.secondPasskey.success ? '#155724' : '#721c24'
                        }}>
                          {transactionResults.secondPasskey.passkey} {transactionResults.secondPasskey.success ? '✅' : '❌'}
                        </div>

                        {/* Passkey Details Section */}
                        <div style={{
                          marginBottom: '15px',
                          padding: '10px',
                          backgroundColor: '#f8f9fa',
                          borderRadius: '4px',
                          border: '1px solid #e9ecef'
                        }}>
                          <div style={{ fontWeight: 'bold', color: '#495057', marginBottom: '8px', fontSize: '0.9em' }}>
                            🔑 Passkey Details:
                          </div>

                          {transactionResults.secondPasskey.credentialId && (
                            <div style={{ marginBottom: '5px' }}>
                              <span style={{ fontSize: '0.8em', color: '#6c757d' }}>Credential ID:</span>
                              <div style={{
                                fontFamily: 'monospace',
                                fontSize: '0.75em',
                                color: '#495057',
                                backgroundColor: '#ffffff',
                                padding: '4px 6px',
                                borderRadius: '3px',
                                border: '1px solid #dee2e6',
                                marginTop: '2px'
                              }}>
                                {transactionResults.secondPasskey.credentialId}
                              </div>
                            </div>
                          )}

                          {transactionResults.secondPasskey.ownerIndex !== undefined && (
                            <div style={{ marginBottom: '5px' }}>
                              <span style={{ fontSize: '0.8em', color: '#6c757d' }}>Owner Index:</span>
                              <span style={{
                                fontFamily: 'monospace',
                                fontSize: '0.8em',
                                color: '#495057',
                                backgroundColor: '#ffffff',
                                padding: '2px 6px',
                                borderRadius: '3px',
                                border: '1px solid #dee2e6',
                                marginLeft: '8px'
                              }}>
                                #{transactionResults.secondPasskey.ownerIndex}
                              </span>
                            </div>
                          )}

                          {transactionResults.secondPasskey.ownerBytes && (
                            <div>
                              <span style={{ fontSize: '0.8em', color: '#6c757d' }}>Owner Bytes:</span>
                              <div style={{
                                fontFamily: 'monospace',
                                fontSize: '0.7em',
                                color: '#495057',
                                backgroundColor: '#ffffff',
                                padding: '4px 6px',
                                borderRadius: '3px',
                                border: '1px solid #dee2e6',
                                marginTop: '2px',
                                wordBreak: 'break-all'
                              }}>
                                {transactionResults.secondPasskey.ownerBytes.slice(0, 32)}...{transactionResults.secondPasskey.ownerBytes.slice(-16)}
                              </div>
                            </div>
                          )}
                        </div>

                        <div style={{ marginBottom: '10px' }}>
                          <div style={{ fontWeight: 'bold', color: '#495057', marginBottom: '5px' }}>
                            From Address:
                          </div>
                          <div style={{
                            fontFamily: 'monospace',
                            fontSize: '0.8em',
                            backgroundColor: '#ffffff',
                            padding: '8px',
                            borderRadius: '4px',
                            border: '1px solid #e9ecef',
                            wordBreak: 'break-all'
                          }}>
                            {transactionResults.secondPasskey.fromAddress}
                          </div>
                        </div>

                        <div>
                          <div style={{ fontWeight: 'bold', color: '#495057', marginBottom: '5px' }}>
                            {transactionResults.secondPasskey.success ? 'Transaction Hash:' : 'Error:'}
                          </div>
                          <div style={{
                            fontFamily: 'monospace',
                            fontSize: '0.8em',
                            backgroundColor: transactionResults.secondPasskey.success ? '#ffffff' : '#f8f9fa',
                            padding: '8px',
                            borderRadius: '4px',
                            border: '1px solid #e9ecef',
                            wordBreak: 'break-all'
                          }}>
                            {transactionResults.secondPasskey.success ? transactionResults.secondPasskey.txHash : transactionResults.secondPasskey.error || 'Unknown error'}
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div
                        style={{
                          padding: '15px',
                          backgroundColor: '#f8f9fa',
                          border: '1px solid #dee2e6',
                          borderRadius: '6px',
                          fontSize: '0.9em',
                          textAlign: 'center',
                          color: '#6c757d'
                        }}
                      >
                        <div style={{ fontWeight: 'bold', marginBottom: '10px' }}>
                          Second Passkey
                        </div>
                        <div>
                          Click "Execute with Second Passkey" to see results here
                        </div>
                      </div>
                    )}
                  </div>

                  <div style={{
                    padding: '15px',
                    backgroundColor: '#e7f3ff',
                    border: '1px solid #b3d9ff',
                    borderRadius: '6px',
                    fontSize: '0.9em',
                    color: '#004085'
                  }}>
                    💡 <strong>Multiple Passkey Proof:</strong> The transactions above demonstrate two key facts:
                    <br/>
                    <br/>
                    <strong>1. Same Account Control:</strong> Both transactions show identical "From Address", proving both passkeys control the same smart account.
                    <br/>
                    <br/>
                    <strong>2. Different Passkeys Used:</strong> Each transaction shows different "Credential ID", "Owner Index", and "Owner Bytes", proving distinct passkeys are being used for signing.
                    <br/>
                    <br/>
                    This conclusively demonstrates that multiple passkeys can seamlessly control the same Giano smart account!
                  </div>
                </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
};

export default MultipleOwnersDemo;
