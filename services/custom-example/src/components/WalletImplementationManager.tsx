import React, { useState, useEffect, useCallback } from 'react';
import { useAccount, useWalletClient, usePublicClient } from 'wagmi';
import { getImplementationAddress, getEntryPointAddress, type SupportedEntryPointVersion } from '../config';

interface WalletImplementationManagerProps {
  onImplementationChange?: (version: SupportedEntryPointVersion) => void;
}

export const WalletImplementationManager: React.FC<WalletImplementationManagerProps> = ({ 
  onImplementationChange 
}) => {
  const { address, isConnected } = useAccount();
  const { data: walletClient } = useWalletClient();
  const publicClient = usePublicClient();
  
  const [currentImplementation, setCurrentImplementation] = useState<string | null>(null);
  const [currentVersion, setCurrentVersion] = useState<SupportedEntryPointVersion | null>(null);
  const [entryPoint, setEntryPoint] = useState<string | null>(null);
  const [isUpgrading, setIsUpgrading] = useState(false);
  const [isDetecting, setIsDetecting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Detect current implementation and version
  const detectWalletVersion = useCallback(async () => {
    if (!publicClient || !address) return;

    try {
      setIsDetecting(true);
      setError(null);

      // First, check if this address has code (is a contract)
      const code = await publicClient.getBytecode({ address: address as `0x${string}` });
      
      if (!code || code === '0x') {
        // This is an EOA (MetaMask/hardware wallet), not a smart wallet
        setCurrentImplementation('EOA');
        setCurrentVersion(null);
        setEntryPoint('N/A - EOA wallet');
        setError('Connected wallet is not a Giano smart wallet. Please create or connect a Giano smart wallet first.');
        return;
      }

      // This is a contract, try to read implementation and entryPoint
      let implAddress: string;
      let epAddress: string;

      try {
        // Get current implementation address
        const implementationResult = await publicClient.readContract({
          address: address as `0x${string}`,
          abi: [
            {
              "inputs": [],
              "name": "implementation",
              "outputs": [{"internalType": "address", "name": "", "type": "address"}],
              "stateMutability": "view",
              "type": "function"
            }
          ],
          functionName: 'implementation',
        });
        implAddress = implementationResult as string;
      } catch (implErr) {
        console.warn('Failed to read implementation:', implErr);
        setError('Connected contract is not a UUPS proxy wallet');
        return;
      }

      try {
        // Get current EntryPoint
        const entryPointResult = await publicClient.readContract({
          address: address as `0x${string}`,
          abi: [
            {
              "inputs": [],
              "name": "entryPoint", 
              "outputs": [{"internalType": "address", "name": "", "type": "address"}],
              "stateMutability": "view",
              "type": "function"
            }
          ],
          functionName: 'entryPoint',
        });
        epAddress = entryPointResult as string;
      } catch (epErr) {
        console.warn('Failed to read entryPoint:', epErr);
        setError('Connected contract does not support ERC-4337');
        return;
      }

      setCurrentImplementation(implAddress);
      setEntryPoint(epAddress);

      // Determine version based on implementation address
      const v07Implementation = getImplementationAddress('0.7');
      const v08Implementation = getImplementationAddress('0.8');

      let detectedVersion: SupportedEntryPointVersion;
      if (implAddress.toLowerCase() === v07Implementation.toLowerCase()) {
        detectedVersion = '0.7';
      } else if (implAddress.toLowerCase() === v08Implementation.toLowerCase()) {
        detectedVersion = '0.8';
      } else {
        console.warn('Unknown implementation address:', implAddress);
        console.warn('Expected V07:', v07Implementation);
        console.warn('Expected V08:', v08Implementation);
        setError(`Unknown Giano wallet implementation. Expected:\nV07: ${v07Implementation}\nV08: ${v08Implementation}\nFound: ${implAddress}`);
        detectedVersion = '0.7'; // Default assumption
      }

      setCurrentVersion(detectedVersion);
      onImplementationChange?.(detectedVersion);

    } catch (err) {
      console.error('Failed to detect wallet version:', err);
      setError(`Failed to detect wallet version: ${(err as Error).message}`);
    } finally {
      setIsDetecting(false);
    }
  }, [publicClient, address, onImplementationChange]);

  // Upgrade wallet to V08 implementation
  const upgradeToV08 = async () => {
    if (!walletClient || !address || currentVersion !== '0.7') return;

    if (!confirm('⚠️ You are about to upgrade your wallet to EntryPoint v0.8. This will change how your wallet interacts with the network but will keep the same address. Continue?')) {
      return;
    }

    try {
      setIsUpgrading(true);
      setError(null);

      const v08Implementation = getImplementationAddress('0.8');
      
      // Call upgradeToAndCall on the wallet
      const tx = await walletClient.writeContract({
        address: address as `0x${string}`,
        abi: [
          {
            "inputs": [
              {"internalType": "address", "name": "newImplementation", "type": "address"},
              {"internalType": "bytes", "name": "data", "type": "bytes"}
            ],
            "name": "upgradeToAndCall",
            "outputs": [],
            "stateMutability": "payable", 
            "type": "function"
          }
        ],
        functionName: 'upgradeToAndCall',
        args: [v08Implementation as `0x${string}`, '0x'], // No initialization data needed
      });

      console.log('Upgrade transaction sent:', tx);
      
      // Wait a bit then re-detect
      setTimeout(() => {
        detectWalletVersion();
      }, 2000);

    } catch (err) {
      console.error('Failed to upgrade wallet:', err);
      setError('Failed to upgrade wallet: ' + (err as Error).message);
    } finally {
      setIsUpgrading(false);
    }
  };

  // Auto-detect when wallet connects
  useEffect(() => {
    if (isConnected && address && publicClient) {
      detectWalletVersion();
    } else {
      setCurrentImplementation(null);
      setCurrentVersion(null);
      setEntryPoint(null);
    }
  }, [isConnected, address, publicClient, detectWalletVersion]);

  if (!isConnected || !address) {
    return null;
  }

  return (
    <div style={{
      padding: '1rem',
      border: '2px solid #e5e7eb',
      borderRadius: '8px',
      marginBottom: '1rem',
      backgroundColor: '#f9fafb',
    }}>
      <h3 style={{ margin: '0 0 1rem 0', fontSize: '1.1rem', fontWeight: 'bold' }}>
        🔧 Wallet Implementation Status
      </h3>

      {isDetecting ? (
        <div style={{ color: '#6b7280' }}>🔍 Detecting wallet version...</div>
      ) : (
        <>
          {currentImplementation !== 'EOA' ? (
            // Smart wallet display
            <>
              <div style={{ marginBottom: '0.5rem' }}>
                <strong>Current Version:</strong>{' '}
                <span style={{
                  color: currentVersion === '0.7' ? '#059669' : '#7c3aed',
                  fontWeight: 'bold'
                }}>
                  EntryPoint v{currentVersion}
                </span>
              </div>

              <div style={{ marginBottom: '0.5rem', fontSize: '0.875rem', color: '#6b7280' }}>
                <strong>Implementation:</strong> {currentImplementation}
              </div>

              <div style={{ marginBottom: '1rem', fontSize: '0.875rem', color: '#6b7280' }}>
                <strong>EntryPoint:</strong> {entryPoint}
              </div>
            </>
          ) : (
            // EOA display
            <div style={{ marginBottom: '1rem' }}>
              <div style={{ marginBottom: '0.5rem' }}>
                <strong>Wallet Type:</strong>{' '}
                <span style={{ color: '#d97706', fontWeight: 'bold' }}>
                  EOA (Externally Owned Account)
                </span>
              </div>
              
              <div style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '0.5rem' }}>
                <strong>Address:</strong> {address}
              </div>
              
              <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>
                This is a standard wallet (MetaMask, hardware wallet, etc.).
                <br />
                To test proxy upgrades, you need a Giano smart wallet.
              </div>
            </div>
          )}

          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            <button
              onClick={detectWalletVersion}
              disabled={isDetecting}
              style={{
                padding: '0.5rem 1rem',
                backgroundColor: '#6b7280',
                color: 'white',
                border: 'none',
                borderRadius: '4px',
                cursor: 'pointer',
                fontSize: '0.875rem',
              }}
            >
              🔄 Refresh
            </button>

            {currentImplementation !== 'EOA' && currentVersion === '0.7' && (
              <button
                onClick={upgradeToV08}
                disabled={isUpgrading}
                style={{
                  padding: '0.5rem 1rem',
                  backgroundColor: '#7c3aed',
                  color: 'white',
                  border: 'none',
                  borderRadius: '4px',
                  cursor: 'pointer',
                  fontSize: '0.875rem',
                  fontWeight: 'bold',
                }}
              >
                {isUpgrading ? '⏳ Upgrading...' : '⬆️ Upgrade to v0.8'}
              </button>
            )}

            {currentImplementation !== 'EOA' && currentVersion === '0.8' && (
              <div style={{
                padding: '0.5rem 1rem',
                backgroundColor: '#10b981',
                color: 'white',
                borderRadius: '4px',
                fontSize: '0.875rem',
                fontWeight: 'bold',
              }}>
                ✅ Latest Version
              </div>
            )}
          </div>

          {error && (
            <div style={{
              marginTop: '0.5rem',
              padding: '0.75rem',
              backgroundColor: currentImplementation === 'EOA' ? '#fff7ed' : '#fef2f2',
              border: `1px solid ${currentImplementation === 'EOA' ? '#fed7aa' : '#fecaca'}`,
              borderRadius: '4px',
              color: currentImplementation === 'EOA' ? '#c2410c' : '#dc2626',
              fontSize: '0.875rem',
            }}>
              <div style={{ fontWeight: 'bold', marginBottom: '0.5rem' }}>
                {currentImplementation === 'EOA' ? '⚠️ EOA Wallet Detected' : '❌ Error'}
              </div>
              <div style={{ marginBottom: '0.5rem' }}>{error}</div>
              
              {currentImplementation === 'EOA' && (
                <div style={{ fontSize: '0.8rem', color: '#92400e' }}>
                  <strong>How to create a Giano smart wallet:</strong>
                  <ol style={{ margin: '0.25rem 0', paddingLeft: '1.2rem' }}>
                    <li>Use the "Create Account" button above</li>
                    <li>Sign the wallet creation transaction</li>
                    <li>Your new Giano smart wallet will be deployed</li>
                    <li>Return here to test the proxy upgrade feature</li>
                  </ol>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
};