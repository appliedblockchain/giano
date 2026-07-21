import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useEffect, useState, type FormEvent } from 'react'
import { Hash } from 'viem'
import { UserOperationReceipt } from 'viem/account-abstraction'
import { WagmiProvider, useAccount, useConnect, useDisconnect, useSendTransaction } from 'wagmi'
import {
  Box,
  Button,
  Card,
  CardContent,
  Container,
  Typography,
  Grid,
  Alert,
  Chip,
  Paper,
  TextField,
  Divider,
  Stack,
  IconButton,
  Tooltip,
  LinearProgress,
} from '@mui/material';
import {
  AccountBalanceWallet,
  Delete,
  ContentCopy,
  Refresh,
  Send,
  Storage,
  Person,
  Warning,
  CheckCircle,
  Error,
} from '@mui/icons-material';
import { config as envConfig } from '../config'
import { createServerConfigForUser, getWalletApiInjection } from '../demo-wagmi-server'
import { gianoConnector } from '../wagmi'

const queryClient = new QueryClient();

function ServerStorageDemo() {
  // Always start with default to avoid hydration mismatch
  const [userId, setUserId] = useState('demo-user-123');
  const [isClient, setIsClient] = useState(false);

  // Helper to get user ID from URL
  const getUserIdFromUrl = () => {
    if (typeof window !== 'undefined') {
      const urlParams = new URLSearchParams(window.location.search);
      return urlParams.get('userId') || 'demo-user-123';
    }
    return 'demo-user-123';
  };

  // Update userId from URL after hydration
  useEffect(() => {
    setIsClient(true);
    const urlUserId = getUserIdFromUrl();
    setUserId(urlUserId);
  }, []);
  const [serverData, setServerData] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [isConnecting, setIsConnecting] = useState(false);
  const [isWaitingReceiptFor, setIsWaitingReceiptFor] = useState<Hash | null>(null);
  const [userOperationReceipt, setUserOperationReceipt] = useState<UserOperationReceipt | null>(null);

  const { connect, connectors } = useConnect();
  const { address, isConnected } = useAccount();
  const { disconnect } = useDisconnect();
  const { sendTransaction } = useSendTransaction();

  // Enhanced disconnect handler with proper cleanup
  const handleDisconnect = async () => {
    console.log('[Demo] Disconnecting...');
    console.log('[Demo] Current state before disconnect:', { isConnected, address });
    try {
      await disconnect();
      console.log('[Demo] Disconnect successful');
    } catch (error) {
      console.error('[Demo] Disconnect error:', error);
    }
  };

  // Function to fetch current wallet-api state for this user's session
  const fetchServerData = async () => {
    setLoading(true);
    try {
      const token = getWalletApiInjection(userId).getSessionToken();
      if (!token) {
        setServerData(null);
        return;
      }
      const headers = { authorization: `Bearer ${token}` };
      const [meRes, credsRes] = await Promise.all([
        fetch(`${envConfig.walletApiUrl}/v1/me`, { headers }),
        fetch(`${envConfig.walletApiUrl}/v1/me/credentials`, { headers }),
      ]);
      if (!meRes.ok || !credsRes.ok) {
        setServerData(null);
        return;
      }
      const me = await meRes.json();
      const { credentials } = await credsRes.json();
      setServerData({ me, credentials });
    } catch (error) {
      console.error('Failed to fetch wallet-api data:', error);
      setServerData(null);
    } finally {
      setLoading(false);
    }
  };

  // Function to log out: revokes the wallet-api session (credentials stay server-side)
  const deletePasskey = async () => {
    if (!confirm('Log out of the wallet-api session? Your passkey and credentials stay on the server; sign in again to resume.')) {
      return;
    }

    try {
      await getWalletApiInjection(userId).logout();
      if (isConnected) {
        disconnect();
      }
      await fetchServerData();
    } catch (error) {
      console.error('Failed to log out:', error);
    }
  };

  // Function to connect with current user ID
  const connectWithUserId = async () => {
    setIsConnecting(true);
    try {
      // Connect using the current connector (which is already configured for the current user)
      connect({ connector: connectors[0] });
    } catch (error) {
      console.error('Failed to connect:', error);
    } finally {
      setIsConnecting(false);
    }
  };

  // Function to switch user configuration
  const switchUserConfig = () => {
    const newUserId = userId === 'demo-user-123' ? 'demo-user-456' : 'demo-user-123';
    setUserId(newUserId);
    window.history.replaceState({}, '', `?userId=${newUserId}`);
  };

  // Function to wait for receipt
  const waitForReceipt = async (userOperationHash: Hash) => {
    setIsWaitingReceiptFor(userOperationHash);
    try {
      const receipt = await gianoConnector.waitForUserOperationReceipt({ hash: userOperationHash });
      setUserOperationReceipt(receipt);
    } catch (error) {
      console.error('Failed to wait for receipt:', error);
    } finally {
      setIsWaitingReceiptFor(null);
    }
  };

  // Function to send empty transaction
  const sendEmptyTx = async (e: FormEvent & { currentTarget: HTMLFormElement }) => {
    e.preventDefault();
    if (!address) return;

    try {
      const result = await sendTransaction({
        to: address,
        value: 0n,
      });
      console.log('Transaction sent:', result);
    } catch (error) {
      console.error('Transaction failed:', error);
    }
  };

  // Load server data on mount and when userId changes
  useEffect(() => {
    if (isClient) {
      fetchServerData();
    }
  }, [isClient, userId]);

  return (
    <Container maxWidth="lg">
      <Box sx={{ py: 4 }}>
        <Typography variant="h3" component="h1" align="center" gutterBottom>
          Server Storage Demo
        </Typography>

        <Typography variant="h6" align="center" color="text.secondary" sx={{ mb: 4 }}>
          Test server-side storage for passkey credentials
        </Typography>

        {/* User Configuration */}
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              User Configuration
            </Typography>
            <Typography variant="body2" color="text.secondary" gutterBottom>
              Current User ID: {userId}
            </Typography>
            
            <Stack direction="row" spacing={2} sx={{ mt: 2 }}>
              <Button
                variant="outlined"
                startIcon={<Person />}
                onClick={switchUserConfig}
              >
                Switch User
              </Button>
              <Button
                variant="outlined"
                startIcon={<Refresh />}
                onClick={fetchServerData}
                disabled={loading}
              >
                {loading ? 'Loading...' : 'Refresh Data'}
              </Button>
            </Stack>
          </CardContent>
        </Card>

        {/* Connection Status */}
        {address && (
          <Alert severity="success" sx={{ mb: 3 }}>
            <Typography variant="h6" gutterBottom>
              Wallet Connected
            </Typography>
            <Typography variant="body2" fontFamily="monospace">
              {address}
            </Typography>
          </Alert>
        )}

        {/* Connection Controls */}
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Connection Controls
            </Typography>
            
            <Stack direction="row" spacing={2} flexWrap="wrap">
              {isConnected ? (
                <Button
                  variant="outlined"
                  startIcon={<AccountBalanceWallet />}
                  onClick={handleDisconnect}
                >
                  Disconnect Wallet
                </Button>
              ) : (
                <Button
                  variant="contained"
                  startIcon={<AccountBalanceWallet />}
                  onClick={connectWithUserId}
                  disabled={isConnecting}
                >
                  {isConnecting ? 'Connecting...' : 'Connect Wallet'}
                </Button>
              )}
              
              <Button
                variant="outlined"
                color="error"
                startIcon={<Delete />}
                onClick={deletePasskey}
              >
                Log out session
              </Button>
            </Stack>
          </CardContent>
        </Card>

        {/* Server Data Display */}
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Server Storage Data
            </Typography>
            
            {loading ? (
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <LinearProgress sx={{ flexGrow: 1 }} />
                <Typography variant="body2">Loading server data...</Typography>
              </Box>
            ) : serverData ? (
              <Box>
                <Typography variant="subtitle1" gutterBottom>
                  Session ({serverData.me?.externalUserId})
                </Typography>
                <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
                  <Typography variant="body2" fontFamily="monospace" sx={{ fontSize: '0.75rem' }}>
                    {JSON.stringify(serverData.me, null, 2)}
                  </Typography>
                </Paper>

                <Typography variant="subtitle1" gutterBottom sx={{ mt: 3 }}>
                  Credentials ({serverData.credentials?.length || 0})
                </Typography>
                {serverData.credentials?.map((credential: any, index: number) => (
                  <Paper key={index} variant="outlined" sx={{ p: 2, mb: 2 }}>
                    <Typography variant="body2" fontFamily="monospace" sx={{ fontSize: '0.75rem' }}>
                      {JSON.stringify(credential, null, 2)}
                    </Typography>
                  </Paper>
                ))}
              </Box>
            ) : (
              <Alert severity="info">
                <Typography variant="body2">
                  No wallet-api session. Connect (register or sign in) to create one.
                </Typography>
              </Alert>
            )}
          </CardContent>
        </Card>

        {/* Transaction Testing */}
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Transaction Testing
            </Typography>
            
            <Box component="form" onSubmit={sendEmptyTx}>
              <Button
                type="submit"
                variant="contained"
                startIcon={<Send />}
                disabled={!isConnected || !address}
                sx={{ mt: 2 }}
              >
                Send Empty Transaction
              </Button>
            </Box>
          </CardContent>
        </Card>

        {/* Receipt Waiting */}
        {isWaitingReceiptFor && (
          <Alert severity="info" sx={{ mb: 3 }}>
            <Typography variant="body2">
              Waiting for receipt for hash: {isWaitingReceiptFor}
            </Typography>
          </Alert>
        )}

        {/* User Operation Receipt */}
        {userOperationReceipt && (
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                User Operation Receipt
              </Typography>
              <Paper variant="outlined" sx={{ p: 2 }}>
                <Typography variant="body2" fontFamily="monospace" sx={{ fontSize: '0.75rem' }}>
                  {JSON.stringify(userOperationReceipt, null, 2)}
                </Typography>
              </Paper>
            </CardContent>
          </Card>
        )}

        {/* Instructions */}
        <Alert severity="info">
          <Typography variant="h6" gutterBottom>
            How This Works
          </Typography>
          <Typography variant="body2">
            1. <strong>User Configuration:</strong> Switch between different user IDs to test server storage
            <br />
            2. <strong>Connection:</strong> Connect with the current user ID to test passkey storage
            <br />
            3. <strong>Server Data:</strong> View stored passkey and public key data on the server
            <br />
            4. <strong>Transaction Testing:</strong> Send transactions to test the wallet functionality
          </Typography>
        </Alert>
      </Box>
    </Container>
  );
}

export default function ServerStorageDemoPage() {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  const getUserIdFromUrl = () => {
    if (typeof window !== 'undefined') {
      const urlParams = new URLSearchParams(window.location.search);
      return urlParams.get('userId') || 'demo-user-123';
    }
    return 'demo-user-123';
  };

  if (!mounted) {
    return (
      <Container maxWidth="lg">
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
            Loading Server Storage Demo...
          </Typography>
        </Box>
      </Container>
    );
  }

  return (
    <WagmiProvider config={createServerConfigForUser(getUserIdFromUrl())}>
      <QueryClientProvider client={queryClient}>
        <ServerStorageDemo />
      </QueryClientProvider>
    </WagmiProvider>
  );
}
