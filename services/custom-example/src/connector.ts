import type { WalletDetailsParams } from '@rainbow-me/rainbowkit';
import type { Chain, EIP1193Provider, Hash, TransactionRequest, Transport } from 'viem';
import { createConnector } from 'wagmi';
import { createGianoProvider } from './provider';

export type SendTransactionFnParams = {
  chain: Chain;
  transport: Transport;
  request: TransactionRequest;
};
export type CreateGianoConnectorParams = {
  details: WalletDetailsParams;
  initialChainId: number;
  sendTransaction: (params: SendTransactionFnParams) => Promise<Hash>;
};

export function gianoConnector({ details, initialChainId, sendTransaction }: CreateGianoConnectorParams) {
  return createConnector(({ chains, transports }) => {
    let provider: EIP1193Provider | null = null;

    provider = createGianoProvider({
      chains,
      transports,
      initialChainId,
      sendTransaction,
    });

    const connector = {
      id: 'giano',
      name: 'Giano Connector',
      type: 'custom',
      connect: async () => {
        const accounts = await provider.request({ method: 'eth_requestAccounts' });
        const chainId = await connector.getChainId();
        console.log({ accounts, chainId });
        return { accounts, chainId };
      },
      disconnect: async () => {
        console.log('disconnect');
      },
      getAccounts: async () => {
        return provider.request({ method: 'eth_accounts' });
      },
      getProvider: async (): Promise<EIP1193Provider> => {
        return provider;
      },
      isAuthorized: async () => {
        console.log('isAuthorized');
        try {
          const accounts = await connector.getAccounts();
          return accounts.length > 0;
        } catch {
          console.log('not authorized');
          return false;
        }
      },
      setup: async () => {
        console.log('setup called');
      },
      switchChain: async ({ chainId }: { chainId: number }) => {
        await provider.request({ method: 'wallet_switchEthereumChain', params: [{ chainId: `0x${chainId.toString(16)}` }] });
        return chains.find((chain) => chain.id === chainId)!;
      },
      getChainId: async () => {
        const chainId = await provider.request({ method: 'eth_chainId' });
        return parseInt(chainId, 16);
      },
      onAccountsChanged: (accounts: string[]) => {
        if (accounts.length === 0) {
          void connector.disconnect();
        }
      },
      onChainChanged: (chainId: string) => {
        console.log('onChainChanged', chainId);
      },
      onDisconnect: () => {
        console.log('onDisconnect');
      },
      ...details,
    };

    return connector;
  });
}
