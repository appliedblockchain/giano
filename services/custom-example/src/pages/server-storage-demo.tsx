import React, { useEffect, useState, type FormEvent } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { WagmiProvider, useAccount, useConnect, useDisconnect, useSendTransaction } from 'wagmi';

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
  const { sendTransaction } = useSendTransaction();

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

  // Function to delete all passkey data
  const deletePasskey = async () => {
    if (
      !confirm(
        '⚠️ This will permanently delete your passkey data. You will lose access to your wallet and need to create a new passkey to reconnect. Continue?',
      )
    ) {
      return;
    }

    try {
      // Clear all data including passkey data (full passkey deletion)
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
      connect({ connector: connectors[0] });
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

  // Send empty transaction function
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

  useEffect(() => {
    void fetchServerData();
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

  return (
    <div style={{ padding: '2rem', maxWidth: '800px', margin: '0 auto' }}>
      <h1>🖥️ Server Storage Demo</h1>

      {!isClient && (
        <div
          style={{
            background: '#f3f4f6',
            border: '1px solid #d1d5db',
            borderRadius: '4px',
            padding: '0.5rem 1rem',
            marginBottom: '1rem',
            fontSize: '14px',
            color: '#6b7280',
          }}
        >
          <strong>Loading configuration...</strong>
        </div>
      )}

      {isClient && (
        <div
          style={{
            background: '#e5e7eb',
            border: '1px solid #9ca3af',
            borderRadius: '4px',
            padding: '0.5rem 1rem',
            marginBottom: '1rem',
            fontSize: '14px',
          }}
        >
          <strong>Currently configured for user:</strong> <code>{getUserIdFromUrl()}</code>
        </div>
      )}

      <div
        style={{
          background: '#f0f9ff',
          border: '1px solid #0284c7',
          borderRadius: '8px',
          padding: '1rem',
          marginBottom: '2rem',
        }}
      >
        <h3>💡 What This Demonstrates</h3>
        <p>This demo shows how Giano can store passkey data entirely on your server instead of localStorage:</p>
        <ul>
          <li>
            ✅ <strong>Passkey IDs</strong> stored on server
          </li>
          <li>
            ✅ <strong>Public keys</strong> stored on server
          </li>
          <li>
            ✅ <strong>No localStorage</strong> dependency
          </li>
          <li>
            ✅ <strong>Multi-user support</strong> with user isolation
          </li>
        </ul>
      </div>

      {/* User Configuration */}
      <div style={{ marginBottom: '2rem', padding: '1rem', border: '1px solid #ccc', borderRadius: '8px' }}>
        <h3>👤 User Configuration</h3>
        <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', marginBottom: '1rem' }}>
          <label>
            User ID:
            <input type="text" value={userId} onChange={(e) => setUserId(e.target.value)} style={{ marginLeft: '0.5rem', padding: '0.25rem' }} />
          </label>
          <button onClick={switchUserConfig} style={primaryButtonStyle}>
            Load Page for {userId}
          </button>
        </div>
        <p>
          <small>
            💡 Each user gets isolated storage on the server. Clicking &quot;Load Page for {userId}&quot; will reload the page with the new user configuration.
          </small>
        </p>
        {isClient && userId !== getUserIdFromUrl() && (
          <div
            style={{
              background: '#fef3c7',
              border: '1px solid #f59e0b',
              borderRadius: '4px',
              padding: '0.5rem',
              marginTop: '0.5rem',
              fontSize: '12px',
            }}
          >
            ⚠️ User ID changed. Click &quot;Load Page for {userId}&quot; to apply changes.
          </div>
        )}
      </div>

      {/* Connection Status */}
      <div style={{ marginBottom: '2rem', padding: '1rem', border: '1px solid #ccc', borderRadius: '8px' }}>
        <h3>🔗 Connection Status</h3>
        {isConnected ? (
          <div>
            <p>
              ✅ Connected: <code>{address}</code>
            </p>
            {isClient && (
              <p>
                <small>
                  📦 Using server storage for user: <strong>{getUserIdFromUrl()}</strong>
                </small>
              </p>
            )}
            <button onClick={() => disconnect()} style={dangerButtonStyle}>
              Disconnect
            </button>
          </div>
        ) : (
          <div>
            <p>❌ Not connected</p>
            {isClient && (
              <p>
                <small>
                  Will connect with server storage for user: <strong>{getUserIdFromUrl()}</strong>
                </small>
              </p>
            )}
            <button
              onClick={connectWithUserId}
              disabled={isConnecting}
              style={{
                ...successButtonStyle,
                opacity: isConnecting ? 0.6 : 1,
                cursor: isConnecting ? 'not-allowed' : 'pointer',
              }}
            >
              {isClient ? (isConnecting ? 'Connecting...' : `Connect as ${getUserIdFromUrl()}`) : 'Connect with Server Storage'}
            </button>
          </div>
        )}
      </div>

      {/* Transaction Operations */}
      {isConnected && (
        <div style={{ marginBottom: '2rem', padding: '1rem', border: '1px solid #ccc', borderRadius: '8px' }}>
          <h3>🔄 Transaction Operations</h3>

          {/* Empty Transaction Section */}
          <div>
            <h4>Send Empty Transaction</h4>
            <form onSubmit={sendEmptyTx} style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginBottom: '1rem' }}>
              <button
                type="submit"
                disabled={!isConnected}
                style={{
                  ...secondaryButtonStyle,
                  opacity: !isConnected ? 0.6 : 1,
                  cursor: !isConnected ? 'not-allowed' : 'pointer',
                }}
              >
                Send Empty Transaction
              </button>
            </form>
            <p style={{ fontSize: '12px', color: '#6b7280', margin: '0.5rem 0' }}>
              💡 Sends a transaction with 0 value to your own address - useful for testing transaction signing
            </p>
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
                cursor: loading ? 'not-allowed' : 'pointer',
              }}
            >
              {loading ? 'Loading...' : 'Refresh'}
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

        <div
          style={{
            background: '#e5e7eb',
            border: '1px solid #9ca3af',
            borderRadius: '4px',
            padding: '0.5rem 1rem',
            marginBottom: '1rem',
            fontSize: '14px',
          }}
        >
          <strong>💡 Storage Info:</strong>
          <br />• <strong>Passkey data</strong> is stored on the server and persists across sessions
          <br />• <strong>Delete Passkey</strong> permanently removes passkey data - you&apos;ll lose wallet access
        </div>

        <div style={{ background: '#1f2937', color: '#f9fafb', padding: '1rem', borderRadius: '4px', overflow: 'auto' }}>
          <pre>{JSON.stringify(serverData, null, 2)}</pre>
        </div>

        {serverData && (
          <div style={{ marginTop: '1rem' }}>
            <p>
              <strong>Data stored for user:</strong> <code>{userId}</code>
            </p>
            <ul>
              {serverData.passkeys?.passkeyId && <li>✅ Passkey ID: Present</li>}
              {serverData.publicKeys && <li>✅ Public Keys: {Object.keys(serverData.publicKeys).length} stored</li>}
            </ul>
          </div>
        )}
      </div>

      {/* Instructions */}
      <div
        style={{
          background: '#fef3c7',
          border: '1px solid #f59e0b',
          borderRadius: '8px',
          padding: '1rem',
        }}
      >
        <h3>📋 How to Test</h3>
        <ol>
          <li>
            <strong>Connect</strong> using the &quot;Connect with Server Storage&quot; button
          </li>
          <li>
            <strong>Create a passkey</strong> when prompted
          </li>
          <li>
            <strong>Send empty transaction</strong> - test transaction signing capability
          </li>
          <li>
            <strong>Check server data</strong> using the &quot;Refresh&quot; button to see stored data
          </li>
          <li>
            <strong>Test disconnection</strong> - click &quot;Disconnect&quot;, then try to connect again (should work with same passkey)
          </li>
          <li>
            <strong>Switch users</strong> by changing the User ID and clicking &quot;Load Page for [User]&quot;
          </li>
          <li>
            <strong>Notice</strong> that different users have isolated data
          </li>
          <li>
            <strong>Delete passkey</strong> - click &quot;Delete Passkey&quot; to permanently remove passkey data (will lose wallet access)
          </li>
          <li>
            <strong>Refresh the page</strong> - your session persists because it&apos;s stored on the server!
          </li>
        </ol>
      </div>

      {/* API Info */}
      <div style={{ marginTop: '2rem', padding: '1rem', border: '1px solid #d1d5db', borderRadius: '8px' }}>
        <h3>🔧 RESTful API Endpoints</h3>
        <ul>
          <li>
            <code>GET /api/storage/users/&#123;userId&#125;/passkeys</code> - Get passkey data
          </li>
          <li>
            <code>PUT /api/storage/users/&#123;userId&#125;/passkeys</code> - Update passkey data
          </li>
          <li>
            <code>GET /api/storage/users/&#123;userId&#125;/public-keys/&#123;idHash&#125;</code> - Get specific public key
          </li>
          <li>
            <code>PUT /api/storage/users/&#123;userId&#125;/public-keys/&#123;idHash&#125;</code> - Store public key
          </li>
          <li>
            <code>DELETE /api/storage/users/&#123;userId&#125;/passkeys</code> - Delete passkey data
          </li>
          <li>
            <code>GET /api/storage/users/&#123;userId&#125;/all</code> - Get all data (demo only)
          </li>
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