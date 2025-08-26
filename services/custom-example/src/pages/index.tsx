import React, { type FormEvent } from 'react';
import { useEffect, useState } from 'react';
import { privateErc20Abi } from '@appliedblockchain/giano-contracts';
import { AccountBalanceWallet, Delete, Refresh, Security, Send, Visibility, VisibilityOff } from '@mui/icons-material';
import { Alert, Box, Button, Card, CardContent, Chip, Container, Divider, Grid, LinearProgress, Paper, Stack, TextField, Typography } from '@mui/material';
import type { NextPage } from 'next';
import Head from 'next/head';
import { encodeFunctionData, formatEther, parseEther } from 'viem';
import { useAccount, useConnect, useDisconnect, useReadContract, useSendTransaction, useWalletClient, useWriteContract } from 'wagmi';
import { config } from '../config';
import { gianoInjection } from '../giano-injection';
import { useGiano } from '../wagmi';

const Home: NextPage = () => {
  const [mounted, setMounted] = useState(false);
  const [connectionReady, setConnectionReady] = useState(false);
  const [isAuthenticating, setIsAuthenticating] = useState(false);
  const [showCredentialList, setShowCredentialList] = useState(false);
  const { gianoConnector } = useGiano();
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

  // Message approval state variables
  const [approvalMessageContent, setApprovalMessageContent] = useState('Hello, please approve this message!');
  const [approvalMessageTimestamp, setApprovalMessageTimestamp] = useState(Math.floor(Date.now() / 1000));
  const [approvalSignature, setApprovalSignature] = useState('');
  const [approvalResult, setApprovalResult] = useState<string>('');
  const [isApprovalPending, setIsApprovalPending] = useState(false);

  // Function to toggle credential list mode
  const toggleCredentialListMode = async () => {
    if (isConnected) {
      // Disconnect first if connected
      disconnect();
    }

    // Toggle the mode
    setShowCredentialList(!showCredentialList);
    gianoInjection.setShowListCredentials(!showCredentialList);
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

  const sendTx = async (e: FormEvent & { currentTarget: HTMLFormElement }) => {
    e.preventDefault();
    if (!inputMessage.trim()) return;

    try {
      const data = encodeFunctionData({
        abi: privateErc20Abi,
        functionName: 'mint',
        args: [parseEther(inputMessage)],
      });

      await writeContractAsync({
        address: config.privateErc20Address as `0x${string}`,
        abi: privateErc20Abi,
        functionName: 'mint',
        args: [parseEther(inputMessage)],
      });
    } catch (error) {
      console.error('Transaction failed:', error);
    }
  };

  const sendEmptyTx = async (e: FormEvent & { currentTarget: HTMLFormElement }) => {
    e.preventDefault();
    try {
      sendTransaction({
        to: address as `0x${string}`,
        value: 0n,
      });
    } catch (error) {
      console.error('Empty transaction failed:', error);
    }
  };

  const prepareManualMint = async () => {
    if (!manualMintAmount.trim()) return;

    try {
      setIsManualMintPending(true);
      const data = encodeFunctionData({
        abi: privateErc20Abi,
        functionName: 'mint',
        args: [parseEther(manualMintAmount)],
      });

      const userOp = await gianoConnector.prepareUserOperation({
        to: config.privateErc20Address as `0x${string}`,
        data,
      });

      setPreparedUserOp(userOp);
      setIsUserOpSigned(false);
      console.log('User operation prepared:', userOp);
    } catch (error) {
      console.error('Failed to prepare user operation:', error);
    } finally {
      setIsManualMintPending(false);
    }
  };

  const signPreparedUserOp = async () => {
    if (!preparedUserOp) return;

    try {
      setIsManualMintPending(true);
      const signedUserOp = await gianoConnector.signUserOperation(preparedUserOp);
      setPreparedUserOp(signedUserOp);
      setIsUserOpSigned(true);
      console.log('User operation signed:', signedUserOp);
    } catch (error) {
      console.error('Failed to sign user operation:', error);
    } finally {
      setIsManualMintPending(false);
    }
  };

  const sendSignedUserOp = async () => {
    if (!preparedUserOp || !isUserOpSigned) return;

    try {
      setIsManualMintPending(true);
      const hash = await gianoConnector.sendUserOperation(preparedUserOp);
      console.log('User operation sent:', hash);
      setPreparedUserOp(null);
      setIsUserOpSigned(false);
      setManualMintAmount('');
    } catch (error) {
      console.error('Failed to send user operation:', error);
    } finally {
      setIsManualMintPending(false);
    }
  };

  const manualMintFullWorkflow = async () => {
    if (!manualMintAmount.trim()) return;

    try {
      setIsManualMintPending(true);
      const data = encodeFunctionData({
        abi: privateErc20Abi,
        functionName: 'mint',
        args: [parseEther(manualMintAmount)],
      });

      const userOp = await gianoConnector.prepareUserOperation({
        to: config.privateErc20Address as `0x${string}`,
        data,
      });

      const signedUserOp = await gianoConnector.signUserOperation(userOp);
      const hash = await gianoConnector.sendUserOperation(signedUserOp);

      console.log('Full workflow completed:', hash);
      setManualMintAmount('');
    } catch (error) {
      console.error('Full workflow failed:', error);
    } finally {
      setIsManualMintPending(false);
    }
  };

  const sendCall = async () => {
    try {
      const result = await readContract();
      setContractState(result.data);
    } catch (error) {
      console.error('Failed to read contract:', error);
    }
  };

  const sendPrivateCall = async () => {
    try {
      setIsPrivateBalanceFetching(true);
      const result = await gianoConnector.readContract({
        address: config.privateErc20Address as `0x${string}`,
        abi: privateErc20Abi,
        functionName: 'balanceOf',
        args: [address!],
      });
      setPrivateContractState(result as bigint);
    } catch (error) {
      console.error('Failed to read private contract:', error);
    } finally {
      setIsPrivateBalanceFetching(false);
    }
  };

  const signMessage = async () => {
    try {
      const signature = await walletClient.request({
        method: 'personal_sign',
        params: [messageToSign, address],
      } as any);

      setSignatureResult(signature as string);
      console.log('Message signed successfully:', signature);
    } catch (error) {
      console.error('Message signing failed:', error);
      setSignatureResult('Error: ' + (error as Error).message);
    }
  };

  const signTypedData = async () => {
    try {
      const typedData = {
        types: {
          EIP712Domain: [
            { name: 'name', type: 'string' },
            { name: 'version', type: 'string' },
            { name: 'chainId', type: 'uint256' },
            { name: 'verifyingContract', type: 'address' },
          ],
          Person: [
            { name: 'name', type: 'string' },
            { name: 'wallet', type: 'address' },
          ],
        },
        primaryType: 'Person',
        domain: {
          name: 'Ether Mail',
          version: '1',
          chainId: 1,
          verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
        },
        message: {
          name: 'Bob',
          wallet: address,
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

  const signMessageForApproval = async () => {
    if (!walletClient || !address) {
      console.error('Wallet not connected');
      return;
    }

    try {
      // Create EIP-712 typed data for message approval
      const typedData = {
        domain: {
          name: 'PrivateERC20',
          version: '1',
          chainId: 1, // This should match the actual chain ID
          verifyingContract: config.privateErc20Address,
        },
        types: {
          // EIP-712 type definitions expected by the contract
          Message: [
            { name: 'content', type: 'string' },
            { name: 'timestamp', type: 'uint256' },
          ],
        },
        primaryType: 'Message',
        message: {
          content: approvalMessageContent,
          timestamp: approvalMessageTimestamp,
        },
      };

      const signature = await walletClient.request({
        method: 'eth_signTypedData_v4',
        params: [address, JSON.stringify(typedData)],
      } as any);

      setApprovalSignature(signature as string);
      setApprovalResult('Message signed successfully! Use the signature below to approve the message.');
      console.log('Message signed for approval:', signature);
    } catch (error) {
      console.error('Message signing for approval failed:', error);
      setApprovalResult('Error: ' + (error as Error).message);
    }
  };

  const approveMessage = async () => {
    if (!address || !approvalSignature) {
      setApprovalResult('Please sign a message first and ensure wallet is connected');
      return;
    }

    try {
      setIsApprovalPending(true);

      // Call the approveMessage function on the contract
      const result = await writeContractAsync({
        address: config.privateErc20Address as `0x${string}`,
        abi: privateErc20Abi,
        functionName: 'approveMessage' as any, // Type assertion needed until TypeScript types are updated
        args: [approvalMessageContent, BigInt(approvalMessageTimestamp), approvalSignature, address],
      });

      setApprovalResult(`Message approved successfully! Transaction: ${result}`);
      console.log('Message approved:', result);
    } catch (error) {
      console.error('Message approval failed:', error);
      setApprovalResult('Error: ' + (error as Error).message);
    } finally {
      setIsApprovalPending(false);
    }
  };

  // Don't render wallet-dependent UI until after hydration
  if (!mounted) {
    return (
      <Container maxWidth="lg">
        <Head>
          <title>Giano Demo</title>
          <meta content="Generated by @rainbow-me/create-rainbowkit" name="description" />
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
            Loading Giano Demo...
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
          <title>Giano Demo</title>
          <meta content="Generated by @rainbow-me/create-rainbowkit" name="description" />
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
        <title>Giano Demo</title>
        <meta content="Generated by @rainbow-me/create-rainbowkit" name="description" />
        <link href="/favicon.ico" rel="icon" />
      </Head>

      {/* Header */}
      <Paper elevation={2} sx={{ p: 3, mb: 3, mt: 2 }}>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} md={4}>
            <Typography variant="h4" component="h1" gutterBottom>
              Giano Demo
            </Typography>
            <Typography variant="subtitle1" color="text.secondary">
              Passkey-based Smart Account Wallet
            </Typography>
          </Grid>
          <Grid item xs={12} md={8}>
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
              <Button variant="outlined" color="error" startIcon={<Delete />} onClick={deletePasskey}>
                Delete Passkey
              </Button>
              <Button variant="outlined" startIcon={showCredentialList ? <VisibilityOff /> : <Visibility />} onClick={toggleCredentialListMode}>
                {showCredentialList ? 'Normal Mode' : 'Credential List Mode'}
              </Button>
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

      {/* Credential Mode Status */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6">Credential Mode</Typography>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2, mt: 1 }}>
            <Chip
              label={showCredentialList ? 'Credential List Mode' : 'Normal Mode'}
              color={showCredentialList ? 'secondary' : 'primary'}
              icon={showCredentialList ? <Visibility /> : <Security />}
            />
          </Box>
          <Typography variant="body2" color="text.secondary">
            <strong>Normal Mode:</strong> Automatically selects credentials from storage
          </Typography>
          <Typography variant="body2" color="text.secondary">
            <strong>Credential List Mode:</strong> Shows a list of available credentials for user selection
          </Typography>
        </CardContent>
      </Card>

      {/* Quick Actions */}
      <Typography variant="h5" gutterBottom>
        Quick Actions
      </Typography>
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Standard Mint
              </Typography>
              <Typography variant="body2" color="text.secondary" gutterBottom>
                Mint tokens using the standard contract interaction
              </Typography>
              <Box component="form" onSubmit={sendTx} sx={{ mt: 2 }}>
                <TextField
                  fullWidth
                  type="number"
                  placeholder="Enter amount"
                  value={inputMessage}
                  onChange={(e) => setInputMessage(e.target.value)}
                  sx={{ mb: 2 }}
                />
                <Button type="submit" variant="contained" fullWidth disabled={!connectionReady || isWritePending || !inputMessage.trim()} startIcon={<Send />}>
                  {isWritePending ? 'Minting...' : 'Mint Tokens'}
                </Button>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Empty Transaction
              </Typography>
              <Typography variant="body2" color="text.secondary" gutterBottom>
                Send an empty transaction to test the wallet
              </Typography>
              <Box component="form" onSubmit={sendEmptyTx} sx={{ mt: 2 }}>
                <Button type="submit" variant="outlined" fullWidth disabled={!connectionReady || isWritePending} startIcon={<Send />}>
                  Send Empty Tx
                </Button>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Advanced: Manual Transaction Building */}
      <Typography variant="h5" gutterBottom>
        Advanced: Manual Transaction Building
      </Typography>
      <Card sx={{ mb: 4 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Step-by-Step User Operation
          </Typography>
          <Typography variant="body2" color="text.secondary" gutterBottom>
            Build and execute transactions manually using the three-step process
          </Typography>

          <TextField
            fullWidth
            type="number"
            placeholder="Amount to mint manually"
            value={manualMintAmount}
            onChange={(e) => setManualMintAmount(e.target.value)}
            sx={{ mb: 3 }}
          />

          <Grid container spacing={2} sx={{ mb: 3 }}>
            <Grid item xs={12} md={4}>
              <Button
                fullWidth
                variant="outlined"
                disabled={!connectionReady || isManualMintPending || !manualMintAmount.trim()}
                onClick={prepareManualMint}
                startIcon={<Typography variant="caption">1</Typography>}
              >
                Prepare UserOp
              </Button>
            </Grid>
            <Grid item xs={12} md={4}>
              <Button
                fullWidth
                variant="outlined"
                disabled={!connectionReady || isManualMintPending || !preparedUserOp || isUserOpSigned}
                onClick={signPreparedUserOp}
                startIcon={<Typography variant="caption">2</Typography>}
              >
                Sign UserOp
              </Button>
            </Grid>
            <Grid item xs={12} md={4}>
              <Button
                fullWidth
                variant="outlined"
                disabled={!connectionReady || isManualMintPending || !isUserOpSigned}
                onClick={sendSignedUserOp}
                startIcon={<Typography variant="caption">3</Typography>}
              >
                Send UserOp
              </Button>
            </Grid>
          </Grid>

          <Divider sx={{ my: 2 }}>
            <Typography variant="body2" color="text.secondary">
              OR
            </Typography>
          </Divider>

          <Button
            variant="contained"
            fullWidth
            disabled={!connectionReady || isManualMintPending || !manualMintAmount.trim()}
            onClick={manualMintFullWorkflow}
            startIcon={<Send />}
          >
            {isManualMintPending ? 'Processing...' : 'Mint (Full Workflow)'}
          </Button>

          {preparedUserOp && (
            <Card variant="outlined" sx={{ mt: 3 }}>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  User Operation Status
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={6}>
                    <Typography variant="body2">
                      <strong>Prepared:</strong> ✅
                    </Typography>
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="body2">
                      <strong>Signed:</strong> {isUserOpSigned ? '✅' : '❌'}
                    </Typography>
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="body2">
                      <strong>Nonce:</strong> {preparedUserOp.nonce}
                    </Typography>
                  </Grid>
                  {preparedUserOp.signature && (
                    <Grid item xs={12}>
                      <Typography variant="body2">
                        <strong>Signature:</strong> {preparedUserOp.signature.slice(0, 20)}...
                      </Typography>
                    </Grid>
                  )}
                </Grid>
              </CardContent>
            </Card>
          )}
        </CardContent>
      </Card>

      {/* Balance Reading */}
      <Typography variant="h5" gutterBottom>
        Balance & Data Reading
      </Typography>
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Public Balance
              </Typography>
              <Typography variant="body2" color="text.secondary" gutterBottom>
                Read your public token balance
              </Typography>
              <Button
                variant="outlined"
                fullWidth
                disabled={!address || !mounted || !connectionReady || !isConnected || isReadFetching}
                onClick={sendCall}
                startIcon={<Refresh />}
                sx={{ mb: 2 }}
              >
                {isReadFetching ? 'Reading...' : 'Read Balance'}
              </Button>
              {contractState && (
                <Alert severity="info">
                  <Typography variant="body2">
                    <strong>Balance:</strong> {formatEther(contractState)} tokens
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
                Private Balance
              </Typography>
              <Typography variant="body2" color="text.secondary" gutterBottom>
                Read your private balance using signed calls
              </Typography>
              <Button
                variant="outlined"
                fullWidth
                disabled={!address || !mounted || !connectionReady || !isConnected || isPrivateBalanceFetching}
                onClick={sendPrivateCall}
                startIcon={<Refresh />}
                sx={{ mb: 2 }}
              >
                {isPrivateBalanceFetching ? 'Reading...' : 'Read Private Balance'}
              </Button>
              {privateContractState && (
                <Alert severity="info">
                  <Typography variant="body2">
                    <strong>Private Balance:</strong> {formatEther(privateContractState)} tokens
                  </Typography>
                </Alert>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Message Signing */}
      <Typography variant="h5" gutterBottom>
        Message Signing
      </Typography>
      <Card sx={{ mb: 4 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Sign Messages
          </Typography>
          <Typography variant="body2" color="text.secondary" gutterBottom>
            Test message signing capabilities
          </Typography>

          <TextField
            fullWidth
            type="text"
            placeholder="Message to sign"
            value={messageToSign}
            onChange={(e) => setMessageToSign(e.target.value)}
            sx={{ mb: 3 }}
          />

          <Stack direction="row" spacing={2} sx={{ mb: 3 }}>
            <Button variant="outlined" disabled={!connectionReady} onClick={signMessage}>
              Sign Message (Personal)
            </Button>
            <Button variant="outlined" disabled={!connectionReady} onClick={signTypedData}>
              Sign Typed Data (EIP-712)
            </Button>
          </Stack>

          {signatureResult && (
            <Card variant="outlined">
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Signature Result
                </Typography>
                <TextField
                  fullWidth
                  multiline
                  rows={3}
                  value={signatureResult}
                  InputProps={{
                    readOnly: true,
                  }}
                  sx={{
                    '& .MuiInputBase-input': {
                      fontFamily: 'monospace',
                      fontSize: '0.875rem',
                    },
                  }}
                />
              </CardContent>
            </Card>
          )}
        </CardContent>
      </Card>

      {/* Message Approval */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" gutterBottom>
          Message Approval with EIP-712
        </Typography>
        <Card variant="outlined">
          <CardContent>
            <Typography variant="h5" gutterBottom>
              Approve Messages
            </Typography>
            <Typography variant="body1" sx={{ mb: 3 }}>
              Sign and approve messages using EIP-712 signatures
            </Typography>

            <Stack spacing={3} sx={{ mb: 3 }}>
              <TextField
                fullWidth
                label="Message Content"
                type="text"
                placeholder="Message content to approve"
                value={approvalMessageContent}
                onChange={(e) => setApprovalMessageContent(e.target.value)}
              />

              <TextField
                fullWidth
                label="Timestamp"
                type="number"
                placeholder="Unix timestamp"
                value={approvalMessageTimestamp}
                onChange={(e) => setApprovalMessageTimestamp(parseInt(e.target.value) || Math.floor(Date.now() / 1000))}
              />
            </Stack>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Button
                  fullWidth
                  variant="outlined"
                  disabled={!connectionReady || !approvalMessageContent}
                  onClick={signMessageForApproval}
                  startIcon={<Typography variant="caption">1</Typography>}
                >
                  Sign Message for Approval
                </Button>
              </Grid>
              <Grid item xs={12} md={6}>
                <Button
                  fullWidth
                  variant="outlined"
                  disabled={!connectionReady || !approvalSignature || isApprovalPending}
                  onClick={approveMessage}
                  startIcon={<Typography variant="caption">2</Typography>}
                >
                  {isApprovalPending ? 'Processing...' : 'Approve Message'}
                </Button>
              </Grid>
            </Grid>

            <Divider sx={{ my: 2 }}>
              <Typography variant="body2" color="text.secondary">
                OR
              </Typography>
            </Divider>

            <Button
              variant="contained"
              fullWidth
              disabled={!connectionReady || !approvalMessageContent || isApprovalPending}
              onClick={async () => {
                await signMessageForApproval();
                await approveMessage();
              }}
              startIcon={<Send />}
            >
              {isApprovalPending ? 'Processing...' : 'Sign & Approve (Full Workflow)'}
            </Button>

            <Stack spacing={2} sx={{ mt: 2 }}>
              {/* Message Approval Status */}
              {(approvalMessageContent || approvalSignature) && (
                <Card variant="outlined" sx={{ mt: 3 }}>
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      Message Approval Status
                    </Typography>
                    <Grid container spacing={2}>
                      <Grid item xs={6}>
                        <Typography variant="body2">
                          <strong>Message:</strong> {approvalMessageContent ? '✅' : '❌'}
                        </Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2">
                          <strong>Signed:</strong> {approvalSignature ? '✅' : '❌'}
                        </Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2">
                          <strong>Timestamp:</strong> {approvalMessageTimestamp}
                        </Typography>
                      </Grid>
                      {approvalSignature && (
                        <Grid item xs={12}>
                          <Typography variant="body2">
                            <strong>Signature:</strong> {approvalSignature.slice(0, 20)}...
                          </Typography>
                        </Grid>
                      )}
                    </Grid>
                  </CardContent>
                </Card>
              )}

              {approvalResult && (
                <Card variant="outlined">
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      Approval Result
                    </Typography>
                    <Typography variant="body2" sx={{ mb: 2 }}>
                      {approvalResult}
                    </Typography>
                    {approvalSignature && (
                      <Box>
                        <Typography variant="subtitle2" gutterBottom>
                          Signature:
                        </Typography>
                        <TextField
                          fullWidth
                          multiline
                          rows={2}
                          value={approvalSignature}
                          InputProps={{
                            readOnly: true,
                          }}
                          sx={{
                            '& .MuiInputBase-input': {
                              fontFamily: 'monospace',
                              fontSize: '0.875rem',
                            },
                          }}
                        />
                      </Box>
                    )}
                  </CardContent>
                </Card>
              )}
            </Stack>
          </CardContent>
        </Card>
      </Box>

      {/* Error Display */}
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          <Typography variant="h6" gutterBottom>
            Error
          </Typography>
          <Typography variant="body2">{error.message}</Typography>
        </Alert>
      )}
    </Container>
  );
};

export default Home;
