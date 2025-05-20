import type { WalletDetailsParams } from '@rainbow-me/rainbowkit';
import type { Chain, EIP1193Provider, TransactionRequest, Transport } from 'viem';
import { createConnector, type CreateConnectorFn } from 'wagmi';

export type SendTransactionFnParams = {
  chain: Chain;
  transport: Transport;
  request: TransactionRequest;
};
export type CreateGianoConnectorParams = {
  details: WalletDetailsParams;
  provider: EIP1193Provider;
};

export function gianoConnector({ details, provider }: CreateGianoConnectorParams): CreateConnectorFn {
  return createConnector(({ chains }) => {
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
        await provider.request({ method: 'wallet_revokePermissions', params: [{ eth_accounts: [] }] });
      },
      getAccounts: async () => {
        console.log('get accounts');
        return provider.request({ method: 'eth_accounts' });
      },
      getProvider: async (): Promise<EIP1193Provider> => {
        console.log('getProvider');
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
        console.log('setup');
      },
      switchChain: async ({ chainId }: { chainId: number }) => {
        await provider.request({ method: 'wallet_switchEthereumChain', params: [{ chainId: `0x${chainId.toString(16)}` }] });
        return chains.find((chain) => chain.id === chainId)!;
      },
      getChainId: async () => {
        const chainId = await provider.request({ method: 'eth_chainId' });
        return parseInt(chainId, 16);
      },
      onAccountsChanged: () => {
        console.log('onAccountsChanged');
      },
      onChainChanged: () => {
        console.log('onChainChanged');
      },
      onDisconnect: () => {
        console.log('onDisconnect');
      },
      ...details,
    };

    return connector;
  });
}
