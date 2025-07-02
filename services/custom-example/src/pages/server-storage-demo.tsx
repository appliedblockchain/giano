import React, { useEffect, useState, type FormEvent } from 'react';
import { privateErc20Abi } from '@appliedblockchain/giano-contracts';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { formatEther, parseEther } from 'viem';
import { WagmiProvider, useAccount, useConnect, useDisconnect, useReadContract, useWriteContract } from 'wagmi';
import { config } from '../config';
import { createServerConfigForUser } from '../demo-wagmi-server';

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

  const { connect, connectors } = useConnect();
  const { address, isConnected } = useAccount();
  const { disconnect } = useDisconnect();

  // Token operation state
  const [mintAmount, setMintAmount] = useState('');
  const [balance, setBalance] = useState<bigint | null>(null);

  // Contract interaction hooks
  const { writeContractAsync, isPending: isMintPending } = useWriteContract();
  const {
    refetch: refetchBalance,
    isFetching: isBalanceFetching,
    error: balanceError,
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

  // Function to fetch current server data
  const fetchServerData = async () => {
    setLoading(true);
    try {
      const response = await fetch(`/api/storage/users/${userId}/all`);
      const data = await response.json();
      setServerData(data.data);
    } catch (error) {
      console.error('Failed to fetch server data:', error);
      setServerData(null);
    } finally {
      setLoading(false);
    }
  };

  // Function to clear only session data
  const clearSessionData = async () => {
    try {
      // Clear only session data (user can reconnect)
      await fetch(`/api/storage/users/${userId}/session`, { method: 'DELETE' });
      await fetchServerData();
    } catch (error) {
      console.error('Failed to clear session data:', error);
    }
  };

    // Function to clear all data including passkey
  const deletePasskey = async () => {
    if (!confirm('⚠️ This will permanently delete your passkey data. You will lose access to your wallet and need to create a new passkey to reconnect. Continue?')) {
      return;
    }
    
    try {
      // Clear all data including passkey data (full passkey deletion)
      await fetch(`/api/storage/users/${userId}/session`, { method: 'DELETE' });
      await fetch(`/api/storage/users/${userId}/passkeys`, { method: 'DELETE' });
      await fetch(`/api/storage/users/${userId}/public-keys`, { method: 'DELETE' });
      
      // Also disconnect if currently connected
      if (isConnected) {
        disconnect();
      }
      
      await fetchServerData();
    } catch (error) {
      console.error('Failed to delete passkey:', error);
    }
  };

  // Function to connect with current user ID
  const connectWithUserId = async () => {
    setIsConnecting(true);
    try {
      // Connect using the current connector (which is already configured for the current user)
      await connect({ connector: connectors[0] });
    } catch (error) {
      console.error('Failed to connect:', error);
    } finally {
      setIsConnecting(false);
    }
  };

  // Function to switch user configuration
  const switchUserConfig = () => {
    // Same as connect - in a real app, you'd redirect or reload
    const currentUrl = new URL(window.location.href);
    currentUrl.searchParams.set('userId', userId);
    window.location.href = currentUrl.toString();
  };

  // Token operation functions
  const mintTokens = async (e: FormEvent & { currentTarget: HTMLFormElement }) => {
    e.preventDefault();
    if (!mintAmount.trim() || !isConnected) return;

    try {
      await writeContractAsync({
        address: config.privateErc20Address,
        abi: privateErc20Abi,
        functionName: 'mint',
        args: [parseEther(mintAmount.trim())],
      });
      setMintAmount(''); // Clear input after successful mint
      // Automatically refresh balance after mint
      setTimeout(() => {
        readBalance();
      }, 1000);
    } catch (error) {
      console.error('Mint failed:', error);
    }
  };

  const readBalance = async () => {
    if (!address || !isConnected) return;

    try {
      const { data } = await refetchBalance();
      if (data) {
        setBalance(data);
      }
    } catch (error) {
      console.error('Failed to read balance:', error);
    }
  };

  useEffect(() => {
    fetchServerData();
  }, [userId]);

  // Common button styles
  const buttonStyle = {
    padding: '0.5rem 1rem',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer',
    fontWeight: '500',
    transition: 'all 0.2s ease',
    fontSize: '14px',
  };

  const primaryButtonStyle = {
    ...buttonStyle,
    background: '#3b82f6',
    color: 'white',
  };

  const secondaryButtonStyle = {
    ...buttonStyle,
    background: '#6366f1',
    color: 'white',
  };

  const successButtonStyle = {
    ...buttonStyle,
    background: '#10b981',
    color: 'white',
  };

  const dangerButtonStyle = {
    ...buttonStyle,
    background: '#ef4444',
    color: 'white',
  };

  const warningButtonStyle = {
    ...buttonStyle,
    background: '#f59e0b',
    color: 'white',
  };

  return (
    <div style={{ padding: '2rem', maxWidth: '800px', margin: '0 auto' }}>
      <h1>🖥️ Server Storage Demo</h1>

      {!isClient && (
        <div style={{
          background: '#f3f4f6',
          border: '1px solid #d1d5db',
          borderRadius: '4px',
          padding: '0.5rem 1rem',
          marginBottom: '1rem',
          fontSize: '14px',
          color: '#6b7280'
        }}>
          <strong>Loading configuration...</strong>
        </div>
      )}

      {isClient && (
        <div style={{
          background: '#e5e7eb',
          border: '1px solid #9ca3af',
          borderRadius: '4px',
          padding: '0.5rem 1rem',
          marginBottom: '1rem',
          fontSize: '14px'
        }}>
          <strong>Currently configured for user:</strong> <code>{getUserIdFromUrl()}</code>
        </div>
      )}

      <div style={{
        background: '#f0f9ff',
        border: '1px solid #0284c7',
        borderRadius: '8px',
        padding: '1rem',
        marginBottom: '2rem'
      }}>
        <h3>💡 What This Demonstrates</h3>
        <p>This demo shows how Giano can store passkey data entirely on your server instead of localStorage:</p>
        <ul>
          <li>✅ <strong>Passkey IDs</strong> stored on server</li>
          <li>✅ <strong>Public keys</strong> stored on server</li>
          <li>✅ <strong>Session data</strong> stored on server</li>
          <li>✅ <strong>No localStorage</strong> dependency</li>
          <li>✅ <strong>Multi-user support</strong> with user isolation</li>
        </ul>
      </div>

      {/* User Configuration */}
      <div style={{ marginBottom: '2rem', padding: '1rem', border: '1px solid #ccc', borderRadius: '8px' }}>
        <h3>👤 User Configuration</h3>
        <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', marginBottom: '1rem' }}>
          <label>
            User ID:
            <input
              type="text"
              value={userId}
              onChange={(e) => setUserId(e.target.value)}
              style={{ marginLeft: '0.5rem', padding: '0.25rem' }}
            />
          </label>
          <button
            onClick={switchUserConfig}
            style={primaryButtonStyle}
          >
            Load Page for {userId}
          </button>
        </div>
        <p><small>💡 Each user gets isolated storage on the server. Clicking "Load Page for {userId}" will reload the page with the new user configuration.</small></p>
        {isClient && userId !== getUserIdFromUrl() && (
          <div style={{
            background: '#fef3c7',
            border: '1px solid #f59e0b',
            borderRadius: '4px',
            padding: '0.5rem',
            marginTop: '0.5rem',
            fontSize: '12px'
          }}>
            ⚠️ User ID changed. Click "Load Page for {userId}" to apply changes.
          </div>
        )}
      </div>

      {/* Connection Status */}
      <div style={{ marginBottom: '2rem', padding: '1rem', border: '1px solid #ccc', borderRadius: '8px' }}>
        <h3>🔗 Connection Status</h3>
        {isConnected ? (
          <div>
            <p>✅ Connected: <code>{address}</code></p>
            {isClient && <p><small>📦 Using server storage for user: <strong>{getUserIdFromUrl()}</strong></small></p>}
            <button
              onClick={() => disconnect()}
              style={dangerButtonStyle}
            >
              Disconnect
            </button>
          </div>
        ) : (
          <div>
            <p>❌ Not connected</p>
            {isClient && <p><small>Will connect with server storage for user: <strong>{getUserIdFromUrl()}</strong></small></p>}
            <button
              onClick={connectWithUserId}
              disabled={isConnecting}
              style={{
                ...successButtonStyle,
                opacity: isConnecting ? 0.6 : 1,
                cursor: isConnecting ? 'not-allowed' : 'pointer'
              }}
            >
              {isClient ? (isConnecting ? 'Connecting...' : `Connect as ${getUserIdFromUrl()}`) : 'Connect with Server Storage'}
            </button>
          </div>
        )}
      </div>

      {/* Token Operations */}
      {isConnected && (
        <div style={{ marginBottom: '2rem', padding: '1rem', border: '1px solid #ccc', borderRadius: '8px' }}>
          <h3>🪙 Token Operations</h3>

          {/* Mint Section */}
          <div style={{ marginBottom: '1.5rem' }}>
            <h4>Mint Tokens</h4>
            <form onSubmit={mintTokens} style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginBottom: '1rem' }}>
              <input
                type="number"
                placeholder="Amount to mint"
                value={mintAmount}
                onChange={(e) => setMintAmount(e.target.value)}
                style={{
                  padding: '0.5rem',
                  border: '1px solid #d1d5db',
                  borderRadius: '4px',
                  flex: 1,
                  maxWidth: '200px'
                }}
              />
              <button
                type="submit"
                disabled={!mintAmount.trim() || isMintPending}
                style={{
                  ...primaryButtonStyle,
                  opacity: (!mintAmount.trim() || isMintPending) ? 0.6 : 1,
                  cursor: (!mintAmount.trim() || isMintPending) ? 'not-allowed' : 'pointer'
                }}
              >
                {isMintPending ? 'Minting...' : 'Mint'}
              </button>
            </form>
          </div>

          {/* Balance Section */}
          <div>
            <h4>Token Balance</h4>
            <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginBottom: '1rem' }}>
              <button
                onClick={readBalance}
                disabled={isBalanceFetching}
                style={{
                  ...secondaryButtonStyle,
                  opacity: isBalanceFetching ? 0.6 : 1,
                  cursor: isBalanceFetching ? 'not-allowed' : 'pointer'
                }}
              >
                {isBalanceFetching ? 'Reading...' : 'Read Balance'}
              </button>
              {balance !== null && (
                <span style={{
                  padding: '0.5rem 1rem',
                  background: '#f0f9ff',
                  border: '1px solid #0284c7',
                  borderRadius: '4px',
                  fontWeight: 'bold'
                }}>
                  Balance: {formatEther(balance)} tokens
                </span>
              )}
            </div>
            {balanceError && (
              <p style={{ color: '#ef4444', fontSize: '14px' }}>
                Error reading balance: {balanceError.message}
              </p>
            )}
          </div>
        </div>
      )}

      {/* Server Data Display */}
      <div style={{ marginBottom: '2rem', padding: '1rem', border: '1px solid #ccc', borderRadius: '8px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <h3>🖥️ Server Storage Data</h3>
          <div>
            <button
              onClick={fetchServerData}
              disabled={loading}
              style={{
                ...secondaryButtonStyle,
                marginRight: '0.5rem',
                opacity: loading ? 0.6 : 1,
                cursor: loading ? 'not-allowed' : 'pointer'
              }}
            >
              {loading ? 'Loading...' : 'Refresh'}
            </button>
            <button
              onClick={clearSessionData}
              style={{...secondaryButtonStyle, marginRight: '0.5rem'}}
              title="Clear session data only - you can still reconnect with the same passkey"
            >
              Clear Session
            </button>
                        <button 
              onClick={deletePasskey}
              style={dangerButtonStyle}
              title="Permanently delete passkey data - you will lose access to your wallet and need to create a new passkey"
            >
              Delete Passkey
            </button>
          </div>
        </div>

        <div style={{
          background: '#e5e7eb',
          border: '1px solid #9ca3af',
          borderRadius: '4px',
          padding: '0.5rem 1rem',
          marginBottom: '1rem',
          fontSize: '14px'
        }}>
          <strong>💡 Button Difference:</strong><br/>
          • <strong>Clear Session</strong>: Removes only login session (credential ID, account address). You can reconnect with the same passkey.<br/>
          • <strong>Delete Passkey</strong>: Permanently removes passkey data. You'll lose access to your wallet and need to create a new passkey.
        </div>

        <div style={{ background: '#1f2937', color: '#f9fafb', padding: '1rem', borderRadius: '4px', overflow: 'auto' }}>
          <pre>{JSON.stringify(serverData, null, 2)}</pre>
        </div>

        {serverData && (
          <div style={{ marginTop: '1rem' }}>
            <p><strong>Data stored for user:</strong> <code>{userId}</code></p>
            <ul>
              {serverData.session?.credentialId && <li>✅ Credential ID: Present</li>}
              {serverData.session?.accountAddress && <li>✅ Account Address: {serverData.session.accountAddress}</li>}
              {serverData.passkeys?.passkeyId && <li>✅ Passkey ID: Present</li>}
              {serverData.publicKeys && <li>✅ Public Keys: {Object.keys(serverData.publicKeys).length} stored</li>}
            </ul>
          </div>
        )}
      </div>

      {/* Instructions */}
      <div style={{
        background: '#fef3c7',
        border: '1px solid #f59e0b',
        borderRadius: '8px',
        padding: '1rem'
      }}>
        <h3>📋 How to Test</h3>
        <ol>
          <li><strong>Connect</strong> using the "Connect with Server Storage" button</li>
          <li><strong>Create a passkey</strong> when prompted</li>
          <li><strong>Try token operations</strong> - mint some tokens and read your balance</li>
          <li><strong>Check server data</strong> using the "Refresh" button to see stored data</li>
          <li><strong>Test disconnection</strong> - click "Disconnect", then try to connect again (should work with same passkey)</li>
          <li><strong>Clear session</strong> - click "Clear Session" to remove session data but keep passkey (can still reconnect)</li>
          <li><strong>Switch users</strong> by changing the User ID and clicking "Load Page for [User]"</li>
          <li><strong>Notice</strong> that different users have isolated data and separate balances</li>
          <li><strong>Delete passkey</strong> - click "Delete Passkey" to permanently remove passkey data (will lose wallet access)</li>
          <li><strong>Refresh the page</strong> - your session persists because it's stored on the server!</li>
        </ol>
      </div>

      {/* API Info */}
      <div style={{ marginTop: '2rem', padding: '1rem', border: '1px solid #d1d5db', borderRadius: '8px' }}>
        <h3>🔧 RESTful API Endpoints</h3>
        <ul>
          <li><code>GET /api/storage/users/&#123;userId&#125;/session</code> - Get session data</li>
          <li><code>PUT /api/storage/users/&#123;userId&#125;/session</code> - Update session data</li>
          <li><code>GET /api/storage/users/&#123;userId&#125;/passkeys</code> - Get passkey data</li>
          <li><code>PUT /api/storage/users/&#123;userId&#125;/passkeys</code> - Update passkey data</li>
          <li><code>GET /api/storage/users/&#123;userId&#125;/public-keys/&#123;idHash&#125;</code> - Get specific public key</li>
          <li><code>PUT /api/storage/users/&#123;userId&#125;/public-keys/&#123;idHash&#125;</code> - Store public key</li>
          <li><code>DELETE /api/storage/users/&#123;userId&#125;/session</code> - Clear session data</li>
          <li><code>GET /api/storage/users/&#123;userId&#125;/all</code> - Get all data (demo only)</li>
        </ul>
      </div>
    </div>
  );
}

export default function ServerStorageDemoPage() {
  // Always start with default config to avoid hydration mismatch
  const [currentUserId, setCurrentUserId] = useState('demo-user-123');
  const [configForUser, setConfigForUser] = useState(() => createServerConfigForUser('demo-user-123'));

  // Get userId from URL to create the right config
  const getUserIdFromUrl = () => {
    if (typeof window !== 'undefined') {
      const urlParams = new URLSearchParams(window.location.search);
      return urlParams.get('userId') || 'demo-user-123';
    }
    return 'demo-user-123';
  };

  // Update config after hydration
  useEffect(() => {
    const urlUserId = getUserIdFromUrl();
    if (urlUserId !== currentUserId) {
      setCurrentUserId(urlUserId);
      setConfigForUser(createServerConfigForUser(urlUserId));
    }
  }, [currentUserId]);

  return (
    <QueryClientProvider client={queryClient}>
      <WagmiProvider config={configForUser} key={currentUserId}>
        <ServerStorageDemo />
      </WagmiProvider>
    </QueryClientProvider>
  );
}