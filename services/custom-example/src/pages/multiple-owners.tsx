import React, { useCallback, useEffect, useState } from 'react';
import {
  GianoEntryPointAddress,
  type GianoEntryPointVersion,
  type GianoSmartAccountImplementation,
  toGianoSmartAccount,
} from '@appliedblockchain/giano-connector/embedded';
import { gianoSmartWalletAbi } from '@appliedblockchain/giano-contracts';
import { AccountBalanceWallet, Add, CheckCircle, ContentCopy, Delete, Error, Refresh, Security, Send, Warning } from '@mui/icons-material';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Container,
  Divider,
  Grid,
  IconButton,
  LinearProgress,
  Paper,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import type { NextPage } from 'next';
import Head from 'next/head';
import { type Call, concatHex, decodeAbiParameters, encodeFunctionData, type Hex, parseGwei, toHex } from 'viem';
import {
  createWebAuthnCredential,
  type SendUserOperationParameters,
  type SmartAccount,
  toWebAuthnAccount,
  type UserOperation,
  type WebAuthnAccount,
} from 'viem/account-abstraction';
import { useAccount, useConnect, useDisconnect, useWalletClient } from 'wagmi';
import { config as envConfig } from '../config';
import { gianoInjection } from '../giano-injection';
import { useGiano } from '../wagmi';

const MultipleOwnersDemo: NextPage = () => {
  const { bundlerClient, gianoClient, gianoConnector } = useGiano();
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
  const [secondPasskeyPublicKey, setSecondPasskeyPublicKey] = useState<{ x: string; y: string } | null>(null);
  const [publicKeyXInput, setPublicKeyXInput] = useState('');
  const [publicKeyYInput, setPublicKeyYInput] = useState('');
  const [isSubmittingPublicKey, setIsSubmittingPublicKey] = useState(false);
  const [publicKeySubmitted, setPublicKeySubmitted] = useState(false);
  const [ownersList, setOwnersList] = useState<
    {
      index: number;
      isPublicKey: boolean;
      fullBytes: string;
      displayValue: string;
    }[]
  >([]);
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
  const [isExecutingFirstPasskey, setIsExecutingFirstPasskey] = useState(false);
  const [isExecutingSecondPasskey, setIsExecutingSecondPasskey] = useState(false);

  // Helper function to create a new WebAuthn credential
  const createNewPasskey = async () => {
    const challenge = new Uint8Array(32);
    crypto.getRandomValues(challenge);

    const userId = new TextEncoder().encode(`user-${Date.now()}-${Math.random()}`);

    const credential = await createWebAuthnCredential({
      rp: {
        name: 'Giano Multiple Owners Demo',
        id: window.location.hostname,
      },
      user: {
        id: userId,
        name: `user-${Date.now()}`,
        displayName: `Demo User ${Date.now()}`,
      },
      challenge,
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        requireResidentKey: true,
        userVerification: 'required',
        residentKey: 'required',
      },
    });

    return credential;
  };

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      // You could add a toast notification here
    } catch (error) {
      console.error('Failed to copy to clipboard:', error);
    }
  };

  const parseOwnerBytes = (ownerBytes: string) => {
    try {
      // Parse the owner bytes to extract information
      const decoded = decodeAbiParameters(
        [
          { name: 'ownerType', type: 'uint8' },
          { name: 'ownerData', type: 'bytes' },
        ],
        ownerBytes as Hex,
      );

      const ownerType = Number(decoded[0]);
      const ownerData = decoded[1];

      if (ownerType === 0) {
        // Public key owner
        const publicKeyDecoded = decodeAbiParameters(
          [
            { name: 'x', type: 'uint256' },
            { name: 'y', type: 'uint256' },
          ],
          ownerData,
        );

        return {
          type: 'public-key',
          x: publicKeyDecoded[0].toString(16),
          y: publicKeyDecoded[1].toString(16),
          fullBytes: ownerBytes,
        };
      } else if (ownerType === 1) {
        // Address owner
        const addressDecoded = decodeAbiParameters([{ name: 'address', type: 'address' }], ownerData);

        return {
          type: 'address',
          address: addressDecoded[0],
          fullBytes: ownerBytes,
        };
      } else {
        return {
          type: 'unknown',
          fullBytes: ownerBytes,
        };
      }
    } catch (error) {
      console.error('Failed to parse owner bytes:', error);
      return {
        type: 'error',
        fullBytes: ownerBytes,
        error: String(error),
      };
    }
  };

  const createSecondPasskey = async () => {
    setIsCreatingSecondPasskey(true);
    try {
      const credential = await createNewPasskey();
      const publicKey = credential.raw?.response?.getPublicKey();

      if (publicKey) {
        const keyData = await crypto.subtle.exportKey('raw', publicKey);
        const keyArray = new Uint8Array(keyData);

        // Extract x and y coordinates (first 32 bytes are x, next 32 bytes are y)
        const x = keyArray.slice(1, 33);
        const y = keyArray.slice(33, 65);

        setSecondPasskeyPublicKey({
          x: toHex(x),
          y: toHex(y),
        });
        setSecondPasskeyCreated(true);
      }
    } catch (error) {
      console.error('Failed to create second passkey:', error);
    } finally {
      setIsCreatingSecondPasskey(false);
    }
  };

  const submitPublicKeyToBlockchain = async () => {
    if (!publicKeyXInput || !publicKeyYInput) return;

    setIsSubmittingPublicKey(true);
    try {
      // Encode the public key as owner bytes
      const ownerBytes = encodeFunctionData({
        abi: gianoSmartWalletAbi,
        functionName: 'addOwnerPublicKey',
        args: [publicKeyXInput as Hex, publicKeyYInput as Hex],
      });

      // Submit the transaction
      const result = await gianoConnector.writeContract({
        address: address as `0x${string}`,
        abi: gianoSmartWalletAbi,
        functionName: 'addOwnerPublicKey',
        args: [publicKeyXInput as Hex, publicKeyYInput as Hex],
      });

      setPublicKeySubmitted(true);
      console.log('Public key submitted:', result);
    } catch (error) {
      console.error('Failed to submit public key:', error);
    } finally {
      setIsSubmittingPublicKey(false);
    }
  };

  const executeTransactionWithFirstPasskey = async () => {
    setIsExecutingFirstPasskey(true);
    try {
      // Create a simple transaction
      const data = encodeFunctionData({
        abi: gianoSmartWalletAbi,
        functionName: 'execute',
        args: [address as `0x${string}`, 0n, '0x'],
      });

      const userOp = await gianoConnector.prepareUserOperation({
        to: address as `0x${string}`,
        data,
      });

      const signedUserOp = await gianoConnector.signUserOperation(userOp);
      const hash = await gianoConnector.sendUserOperation(signedUserOp);

      setTransactionResults((prev) => ({
        ...prev,
        firstPasskey: {
          passkey: 'First Passkey',
          txHash: hash,
          success: true,
          fromAddress: address!,
        },
      }));

      setFirstPasskeyUsed(true);
    } catch (error) {
      console.error('Failed to execute with first passkey:', error);
      setTransactionResults((prev) => ({
        ...prev,
        firstPasskey: {
          passkey: 'First Passkey',
          txHash: '',
          success: false,
          fromAddress: address!,
          error: String(error),
        },
      }));
    } finally {
      setIsExecutingFirstPasskey(false);
    }
  };

  const getWebAuthnAccount = async ({
    credentialId,
    challenge,
  }: {
    credentialId?: BufferSource;
    challenge?: BufferSource;
  } = {}): Promise<WebAuthnAccount | null> => {
    const generateRandomChallenge = () => {
      const challenge = new Uint8Array(32);
      crypto.getRandomValues(challenge);
      return challenge;
    };

    try {
      const account = await toWebAuthnAccount({
        rp: {
          name: 'Giano Multiple Owners Demo',
          id: window.location.hostname,
        },
        challenge: challenge || generateRandomChallenge(),
        credentialId: credentialId || new Uint8Array(0),
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          requireResidentKey: true,
          userVerification: 'required',
          residentKey: 'required',
        },
      });

      return account;
    } catch (error) {
      console.error('Failed to get WebAuthn account:', error);
      return null;
    }
  };

  const submitUserOperation = async (
    userOpRequest: SendUserOperationParameters<SmartAccount<GianoSmartAccountImplementation>, undefined, Call[]> & {
      account: SmartAccount<GianoSmartAccountImplementation>;
    },
  ) => {
    try {
      const userOp = await bundlerClient.sendUserOperation(userOpRequest);
      return userOp;
    } catch (error) {
      console.error('Failed to submit user operation:', error);
      throw error;
    }
  };

  const executeTransactionWithSecondPasskey = async () => {
    setIsExecutingSecondPasskey(true);
    try {
      // Get the second passkey account
      const secondAccount = await getWebAuthnAccount();

      if (!secondAccount) {
        throw new Error('Failed to get second passkey account');
      }

      // Create a transaction
      const data = encodeFunctionData({
        abi: gianoSmartWalletAbi,
        functionName: 'execute',
        args: [address as `0x${string}`, 0n, '0x'],
      });

      const userOp = await secondAccount.prepareUserOperation({
        to: address as `0x${string}`,
        data,
      });

      const signedUserOp = await secondAccount.signUserOperation(userOp);
      const hash = await submitUserOperation({
        ...signedUserOp,
        account: secondAccount,
      });

      setTransactionResults((prev) => ({
        ...prev,
        secondPasskey: {
          passkey: 'Second Passkey',
          txHash: hash,
          success: true,
          fromAddress: address!,
        },
      }));

      setSecondPasskeyUsed(true);
    } catch (error) {
      console.error('Failed to execute with second passkey:', error);
      setTransactionResults((prev) => ({
        ...prev,
        secondPasskey: {
          passkey: 'Second Passkey',
          txHash: '',
          success: false,
          fromAddress: address!,
          error: String(error),
        },
      }));
    } finally {
      setIsExecutingSecondPasskey(false);
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

  useEffect(() => {
    if (mounted && isConnected && status === 'connected') {
      const connectAsync = async () => {
        try {
          setIsAuthenticating(true);
          await new Promise((resolve) => setTimeout(resolve, 1000));
          setConnectionReady(true);
        } catch (error) {
          console.error('Connection setup failed:', error);
        } finally {
          setIsAuthenticating(false);
        }
      };

      connectAsync();
    } else {
      setConnectionReady(false);
    }
  }, [mounted, isConnected, status]);

  // Don't render wallet-dependent UI until after hydration
  if (!mounted) {
    return (
      <Container maxWidth="lg">
        <Head>
          <title>Multiple Owners Demo - Giano</title>
          <meta content="Multiple owners demo with passkeys" name="description" />
          <link href="/favicon.ico" rel="icon" />
        </Head>
        <Box
          sx={{
            minHeight: '100vh',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <LinearProgress sx={{ width: '100%', maxWidth: 400, mb: 2 }} />
          <Typography variant="h6" color="text.secondary">
            Loading Multiple Owners Demo...
          </Typography>
        </Box>
      </Container>
    );
  }

  // Show authentication loading state
  if (isAuthenticating) {
    return (
      <Container maxWidth="lg">
        <Head>
          <title>Multiple Owners Demo - Giano</title>
          <meta content="Multiple owners demo with passkeys" name="description" />
          <link href="/favicon.ico" rel="icon" />
        </Head>
        <Box
          sx={{
            minHeight: '100vh',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <LinearProgress sx={{ width: '100%', maxWidth: 400, mb: 2 }} />
          <Typography variant="h6" color="text.secondary" gutterBottom>
            Authenticating with passkey...
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Please complete the authentication prompt
          </Typography>
        </Box>
      </Container>
    );
  }

  return (
    <Container maxWidth="lg">
      <Head>
        <title>Multiple Owners Demo - Giano</title>
        <meta content="Multiple owners demo with passkeys" name="description" />
        <link href="/favicon.ico" rel="icon" />
      </Head>

      {/* Header */}
      <Paper elevation={2} sx={{ p: 3, mb: 3, mt: 2 }}>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} md={6}>
            <Typography variant="h4" component="h1" gutterBottom>
              Multiple Owners Demo
            </Typography>
            <Typography variant="subtitle1" color="text.secondary">
              Test multiple passkey owners for smart account
            </Typography>
          </Grid>
          <Grid item xs={12} md={6}>
            <Stack direction="row" spacing={2} justifyContent="flex-end" flexWrap="wrap">
              {isConnected ? (
                <Button variant="outlined" startIcon={<AccountBalanceWallet />} onClick={() => disconnect()}>
                  Disconnect Wallet
                </Button>
              ) : (
                <Button variant="contained" startIcon={<AccountBalanceWallet />} onClick={() => connect({ connector: gianoConnector })}>
                  Connect Wallet
                </Button>
              )}
            </Stack>
          </Grid>
        </Grid>
      </Paper>

      {/* Connection Status */}
      {address && (
        <Alert severity="success" sx={{ mb: 3 }}>
          <Typography variant="h6" gutterBottom>
            Wallet Connected
          </Typography>
          <Typography variant="body2" fontFamily="monospace">
            {address}
          </Typography>
          {!connectionReady && (
            <Typography variant="body2" sx={{ mt: 1 }}>
              Initializing smart account...
            </Typography>
          )}
        </Alert>
      )}

      {/* Step 1: Create Second Passkey */}
      <Typography variant="h5" gutterBottom>
        Step 1: Create Second Passkey
      </Typography>
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Create Additional Passkey
          </Typography>
          <Typography variant="body2" color="text.secondary" gutterBottom>
            Create a second passkey that will be added as an owner to your smart account
          </Typography>

          <Button variant="contained" startIcon={<Add />} onClick={createSecondPasskey} disabled={isCreatingSecondPasskey || !connectionReady} sx={{ mt: 2 }}>
            {isCreatingSecondPasskey ? 'Creating...' : 'Create Second Passkey'}
          </Button>

          {secondPasskeyCreated && secondPasskeyPublicKey && (
            <Alert severity="success" sx={{ mt: 2 }}>
              <Typography variant="h6" gutterBottom>
                Second Passkey Created Successfully!
              </Typography>
              <Typography variant="body2" gutterBottom>
                Public Key Coordinates:
              </Typography>
              <Box sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                <div>X: {secondPasskeyPublicKey.x}</div>
                <div>Y: {secondPasskeyPublicKey.y}</div>
              </Box>
              <Button
                size="small"
                startIcon={<ContentCopy />}
                onClick={() => copyToClipboard(`${secondPasskeyPublicKey.x}\n${secondPasskeyPublicKey.y}`)}
                sx={{ mt: 1 }}
              >
                Copy Coordinates
              </Button>
            </Alert>
          )}
        </CardContent>
      </Card>

      {/* Step 2: Submit Public Key */}
      <Typography variant="h5" gutterBottom>
        Step 2: Submit Public Key to Blockchain
      </Typography>
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Add Public Key as Owner
          </Typography>
          <Typography variant="body2" color="text.secondary" gutterBottom>
            Submit the public key coordinates to add the second passkey as an owner
          </Typography>

          <Grid container spacing={2} sx={{ mt: 2 }}>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="Public Key X Coordinate"
                value={publicKeyXInput}
                onChange={(e) => setPublicKeyXInput(e.target.value)}
                placeholder="0x..."
                helperText="Enter the X coordinate of the public key"
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="Public Key Y Coordinate"
                value={publicKeyYInput}
                onChange={(e) => setPublicKeyYInput(e.target.value)}
                placeholder="0x..."
                helperText="Enter the Y coordinate of the public key"
              />
            </Grid>
          </Grid>

          <Button
            variant="contained"
            startIcon={<Send />}
            onClick={submitPublicKeyToBlockchain}
            disabled={isSubmittingPublicKey || !publicKeyXInput || !publicKeyYInput || !connectionReady}
            sx={{ mt: 2 }}
          >
            {isSubmittingPublicKey ? 'Submitting...' : 'Submit Public Key'}
          </Button>

          {publicKeySubmitted && (
            <Alert severity="success" sx={{ mt: 2 }}>
              <Typography variant="body2">Public key submitted successfully to the blockchain!</Typography>
            </Alert>
          )}
        </CardContent>
      </Card>

      {/* Step 3: Execute Transactions */}
      <Typography variant="h5" gutterBottom>
        Step 3: Execute Transactions with Different Passkeys
      </Typography>
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Execute with First Passkey
              </Typography>
              <Typography variant="body2" color="text.secondary" gutterBottom>
                Execute a transaction using the original passkey
              </Typography>

              <Button
                variant="contained"
                fullWidth
                disabled={isExecutingFirstPasskey || !connectionReady}
                onClick={executeTransactionWithFirstPasskey}
                startIcon={<Send />}
                sx={{ mt: 2 }}
              >
                {isExecutingFirstPasskey ? 'Executing...' : 'Execute with First Passkey'}
              </Button>

              {transactionResults.firstPasskey && (
                <Alert severity={transactionResults.firstPasskey.success ? 'success' : 'error'} sx={{ mt: 2 }}>
                  <Typography variant="body2">
                    <strong>Result:</strong> {transactionResults.firstPasskey.success ? 'Success' : 'Failed'}
                    {transactionResults.firstPasskey.txHash && <div>Hash: {transactionResults.firstPasskey.txHash}</div>}
                    {transactionResults.firstPasskey.error && <div>Error: {transactionResults.firstPasskey.error}</div>}
                  </Typography>
                </Alert>
              )}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Execute with Second Passkey
              </Typography>
              <Typography variant="body2" color="text.secondary" gutterBottom>
                Execute a transaction using the second passkey
              </Typography>

              <Button
                variant="contained"
                fullWidth
                disabled={isExecutingSecondPasskey || !connectionReady || !secondPasskeyCreated}
                onClick={executeTransactionWithSecondPasskey}
                startIcon={<Send />}
                sx={{ mt: 2 }}
              >
                {isExecutingSecondPasskey ? 'Executing...' : 'Execute with Second Passkey'}
              </Button>

              {transactionResults.secondPasskey && (
                <Alert severity={transactionResults.secondPasskey.success ? 'success' : 'error'} sx={{ mt: 2 }}>
                  <Typography variant="body2">
                    <strong>Result:</strong> {transactionResults.secondPasskey.success ? 'Success' : 'Failed'}
                    {transactionResults.secondPasskey.txHash && <div>Hash: {transactionResults.secondPasskey.txHash}</div>}
                    {transactionResults.secondPasskey.error && <div>Error: {transactionResults.secondPasskey.error}</div>}
                  </Typography>
                </Alert>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Results Summary */}
      {(transactionResults.firstPasskey || transactionResults.secondPasskey) && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Transaction Results Summary
            </Typography>

            <Grid container spacing={2}>
              {transactionResults.firstPasskey && (
                <Grid item xs={12} md={6}>
                  <Paper variant="outlined" sx={{ p: 2 }}>
                    <Typography variant="subtitle1" gutterBottom>
                      First Passkey
                    </Typography>
                    <Typography variant="body2">Status: {transactionResults.firstPasskey.success ? '✅ Success' : '❌ Failed'}</Typography>
                    {transactionResults.firstPasskey.txHash && (
                      <Typography variant="body2" fontFamily="monospace" sx={{ fontSize: '0.75rem' }}>
                        Hash: {transactionResults.firstPasskey.txHash}
                      </Typography>
                    )}
                  </Paper>
                </Grid>
              )}

              {transactionResults.secondPasskey && (
                <Grid item xs={12} md={6}>
                  <Paper variant="outlined" sx={{ p: 2 }}>
                    <Typography variant="subtitle1" gutterBottom>
                      Second Passkey
                    </Typography>
                    <Typography variant="body2">Status: {transactionResults.secondPasskey.success ? '✅ Success' : '❌ Failed'}</Typography>
                    {transactionResults.secondPasskey.txHash && (
                      <Typography variant="body2" fontFamily="monospace" sx={{ fontSize: '0.75rem' }}>
                        Hash: {transactionResults.secondPasskey.txHash}
                      </Typography>
                    )}
                  </Paper>
                </Grid>
              )}
            </Grid>

            <Button variant="outlined" startIcon={<Delete />} onClick={clearResults} sx={{ mt: 2 }}>
              Clear Results
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Instructions */}
      <Alert severity="info">
        <Typography variant="h6" gutterBottom>
          How This Works
        </Typography>
        <Typography variant="body2">
          1. <strong>Create Second Passkey:</strong> Generate a new passkey that will be added as an owner
          <br />
          2. <strong>Submit Public Key:</strong> Add the public key to the blockchain as an owner
          <br />
          3. <strong>Execute Transactions:</strong> Test transactions with both passkeys to verify multiple ownership
        </Typography>
      </Alert>
    </Container>
  );
};

export default MultipleOwnersDemo;
