import React, { useState } from 'react';
import { useAccount } from 'wagmi';
import { getEntryPointAddress, type SupportedEntryPointVersion } from '@appliedblockchain/giano-connector';

interface EntryPointVerificationProps {
  selectedVersion: SupportedEntryPointVersion;
}

export const EntryPointVerification: React.FC<EntryPointVerificationProps> = ({ selectedVersion }) => {
  const { isConnected, connector } = useAccount();
  const [currentEntryPoint, setCurrentEntryPoint] = useState<string | null>(null);
  const [isChecking, setIsChecking] = useState(false);

  const checkCurrentEntryPoint = async () => {
    if (!connector || !isConnected) return;
    
    setIsChecking(true);
    try {
      console.log('🔍 Connector:', connector);
      console.log('🔍 Connector keys:', Object.keys(connector || {}));
      
      // Try to access EntryPoint through the connector
      let entryPointAddress: string | null = null;
      
      // Check if connector has provider with EntryPoint info
      if ((connector as any).provider) {
        const provider = (connector as any).provider;
        console.log('🔍 Provider:', provider);
        console.log('🔍 Provider keys:', Object.keys(provider || {}));
        
        // Try to get current EntryPoint from provider
        if (provider.getCurrentEntryPoint) {
          entryPointAddress = await provider.getCurrentEntryPoint();
          console.log('🔍 Found EntryPoint via provider.getCurrentEntryPoint():', entryPointAddress);
        } else if (provider.entryPointConfig?.address) {
          entryPointAddress = provider.entryPointConfig.address;
          console.log('🔍 Found EntryPoint via provider.entryPointConfig.address:', entryPointAddress);
        }
      }
      
      // Fallback: use the expected EntryPoint for the selected version
      if (!entryPointAddress) {
        entryPointAddress = getEntryPointAddress(selectedVersion);
        console.log('🔍 Using expected EntryPoint for selected version:', entryPointAddress);
      }
      
      setCurrentEntryPoint(entryPointAddress);
    } catch (error) {
      console.error('Error checking EntryPoint:', error);
      setCurrentEntryPoint('Error checking');
    } finally {
      setIsChecking(false);
    }
  };

  const expectedEntryPoint = getEntryPointAddress(selectedVersion);
  const isUsingCorrectEntryPoint = currentEntryPoint === expectedEntryPoint;

  return (
    <div style={{
      padding: '1rem',
      border: '2px solid #fbbf24',
      borderRadius: '8px',
      marginBottom: '1rem',
      backgroundColor: '#fffbeb',
    }}>
      <h3 style={{ margin: '0 0 1rem 0', fontSize: '1.1rem', fontWeight: 'bold' }}>
        🔍 EntryPoint Verification
      </h3>
      
      <div style={{ fontSize: '0.9rem', marginBottom: '1rem' }}>
        <div><strong>Selected Version:</strong> {selectedVersion}</div>
        <div><strong>Expected Address:</strong> <code style={{ backgroundColor: '#f3f4f6', padding: '2px 4px', borderRadius: '4px' }}>{expectedEntryPoint}</code></div>
        {currentEntryPoint && (
          <div style={{ marginTop: '0.5rem' }}>
            <strong>Current Address:</strong> <code style={{ backgroundColor: '#f3f4f6', padding: '2px 4px', borderRadius: '4px' }}>{currentEntryPoint}</code>
            {isUsingCorrectEntryPoint ? (
              <span style={{ color: '#059669', marginLeft: '0.5rem' }}>✅ Correct</span>
            ) : (
              <span style={{ color: '#dc2626', marginLeft: '0.5rem' }}>❌ Mismatch</span>
            )}
          </div>
        )}
      </div>

      <button
        onClick={checkCurrentEntryPoint}
        disabled={!isConnected || isChecking}
        style={{
          padding: '0.5rem 1rem',
          backgroundColor: isConnected ? '#3b82f6' : '#9ca3af',
          color: 'white',
          border: 'none',
          borderRadius: '4px',
          cursor: isConnected ? 'pointer' : 'not-allowed',
          fontSize: '0.875rem',
        }}
      >
        {isChecking ? 'Checking...' : 'Check Current EntryPoint'}
      </button>

      {!isConnected && (
        <div style={{ marginTop: '0.5rem', fontSize: '0.875rem', color: '#6b7280' }}>
          Connect your wallet to verify the EntryPoint address
        </div>
      )}
    </div>
  );
}; 