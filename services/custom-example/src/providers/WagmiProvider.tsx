import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { WagmiProvider } from 'wagmi';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { createWagmiConfigWithEntryPoint } from '../wagmi';
import { config as envConfig, type SupportedEntryPointVersion } from '../config';
import type { Config } from 'wagmi';

interface DynamicWagmiContextType {
  selectedEntryPointVersion: SupportedEntryPointVersion;
  setSelectedEntryPointVersion: (version: SupportedEntryPointVersion) => void;
  isReconfiguring: boolean;
}

const DynamicWagmiContext = createContext<DynamicWagmiContextType | null>(null);

export const useDynamicWagmi = () => {
  const context = useContext(DynamicWagmiContext);
  if (!context) {
    throw new Error('useDynamicWagmi must be used within DynamicWagmiProvider');
  }
  return context;
};

interface DynamicWagmiProviderProps {
  children: ReactNode;
}

export const DynamicWagmiProvider: React.FC<DynamicWagmiProviderProps> = ({ children }) => {
  const [selectedEntryPointVersion, setSelectedEntryPointVersion] = useState<SupportedEntryPointVersion>(envConfig.defaultEntryPointVersion);
  const [wagmiConfig, setWagmiConfig] = useState<Config>(() => {
    const initialConfig = createWagmiConfigWithEntryPoint(envConfig.defaultEntryPointVersion);
    return initialConfig.config;
  });
  const [isReconfiguring, setIsReconfiguring] = useState(false);
  const [queryClient] = useState(() => new QueryClient());

  const handleEntryPointVersionChange = async (newVersion: SupportedEntryPointVersion) => {
    if (newVersion === selectedEntryPointVersion) return;
    
    console.log('🔄 Reconfiguring Wagmi for EntryPoint version:', newVersion);
    setIsReconfiguring(true);
    
    try {
      // Small delay to allow UI to update
      await new Promise(resolve => setTimeout(resolve, 100));
      
      // Create new wagmi configuration with the selected EntryPoint version
      const newWagmiConfig = createWagmiConfigWithEntryPoint(newVersion);
      
      console.log('✅ New Wagmi config created for EntryPoint version:', newVersion);
      console.log('   Config connector count:', newWagmiConfig.config.connectors.length);
      
      // Update the configuration
      setWagmiConfig(newWagmiConfig.config);
      setSelectedEntryPointVersion(newVersion);
      
    } catch (error) {
      console.error('❌ Error reconfiguring Wagmi:', error);
    } finally {
      setIsReconfiguring(false);
    }
  };

  const contextValue: DynamicWagmiContextType = {
    selectedEntryPointVersion,
    setSelectedEntryPointVersion: handleEntryPointVersionChange,
    isReconfiguring,
  };

  return (
    <DynamicWagmiContext.Provider value={contextValue}>
      <QueryClientProvider client={queryClient}>
        <WagmiProvider config={wagmiConfig} key={`wagmi-${selectedEntryPointVersion}`}>
          {children}
        </WagmiProvider>
      </QueryClientProvider>
    </DynamicWagmiContext.Provider>
  );
}; 