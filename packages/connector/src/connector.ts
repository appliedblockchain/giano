import type { Chain, TransactionRequest, Transport } from 'viem'
import { Hash } from 'viem'
import { UserOperationReceipt } from 'viem/account-abstraction'
import { Connector, createConnector } from 'wagmi'
import { GianoProvider } from './provider'

export type SendTransactionFnParams = {
  chain: Chain;
  transport: Transport;
  request: TransactionRequest;
};
export type CreateGianoConnectorParams = {
  provider: GianoProvider;
};

type GianoConnectorProperties = {
  waitForUserOperationReceipt: (hash: Hash) => Promise<UserOperationReceipt>;
}

export function createGianoConnector({ provider }: CreateGianoConnectorParams) {
  return createConnector<
    GianoProvider,
    GianoConnectorProperties
  >(({ chains }) => {
    const connector = <const>{
      id: 'giano',
      name: 'Giano Connector',
      type: 'custom',
      connect: async () => {
        const accounts = await provider.request({ method: 'eth_requestAccounts' });
        const chainId = await connector.getChainId();
        return { accounts, chainId };
      },
      disconnect: async () => {
        await provider.request({ method: 'wallet_revokePermissions', params: [{ eth_accounts: [] }] });
      },
      getAccounts: async () => {
        return provider.request({ method: 'eth_accounts' });
      },
      getProvider: async () => {
        return provider;
      },
      isAuthorized: async () => {
        try {
          // Check if we have stored session data
          const storedCredentialId = typeof window !== 'undefined' ? localStorage.getItem('giano_credential_id') : null;
          const storedAccountAddress = typeof window !== 'undefined' ? localStorage.getItem('giano_account_address') : null;

          if (storedCredentialId && storedAccountAddress) {
            return true;
          }

          const accounts = await connector.getAccounts();
          return accounts.length > 0;
        } catch {
          return false;
        }
      },
      setup: async () => {
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
      },
      onChainChanged: () => {
      },
      onDisconnect: () => {
      },
      waitForUserOperationReceipt: async (hash: Hash) => {
        return provider.request({
          method: 'waitForUserOperationReceipt',
          params: [hash],
        });
      },
    };

    return connector;
  });
}
