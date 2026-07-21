import type { Address, Chain, TransactionRequest, Transport } from 'viem'
import { Hash } from 'viem'
import { UserOperationReceipt } from 'viem/account-abstraction'
import { createConnector } from 'wagmi'
import type { GianoWalletProvider } from './thin/create-giano-wallet-provider'

export type SendTransactionFnParams = {
  chain: Chain;
  transport: Transport;
  request: TransactionRequest;
};

/**
 * Structural provider surface the connector needs — satisfied both by the thin
 * `createGianoWalletProvider` (default) and by the embedded-mode `GianoProvider`
 * from @appliedblockchain/giano-wallet-core.
 */
export type GianoProviderLike = {
  request: (args: { method: string; params?: unknown }) => Promise<unknown>;
  on: (event: never, listener: never) => unknown;
  removeListener: (event: never, listener: never) => unknown;
};

export type CreateGianoConnectorParams = {
  provider: GianoProviderLike | GianoWalletProvider;
};

type GianoConnectorProperties = {
  waitForUserOperationReceipt: (hash: Hash) => Promise<UserOperationReceipt>;
}

export function createGianoConnector({ provider }: CreateGianoConnectorParams) {
  return createConnector<
    GianoProviderLike,
    GianoConnectorProperties
  >(({ chains }) => {
    const request = (method: string, params?: unknown) => (provider as GianoProviderLike).request({ method, params });

    const connector = <const>{
      id: 'giano',
      name: 'Giano Connector',
      type: 'custom',
      connect: async () => {
        const accounts = (await request('eth_requestAccounts')) as readonly Address[];
        const chainId = await connector.getChainId();
        return { accounts, chainId };
      },
      disconnect: async () => {
        await request('wallet_revokePermissions', [{ eth_accounts: [] }]);
      },
      getAccounts: async () => {
        return (await request('eth_accounts')) as readonly Address[];
      },
      getProvider: async () => {
        return provider as GianoProviderLike;
      },
      isAuthorized: async () => {
        try {
          const accounts = await connector.getAccounts();
          return accounts.length > 0;
        } catch {
          return false;
        }
      },
      setup: async () => {
      },
      switchChain: async ({ chainId }: { chainId: number }) => {
        await request('wallet_switchEthereumChain', [{ chainId: `0x${chainId.toString(16)}` }]);
        return chains.find((chain) => chain.id === chainId)!;
      },
      getChainId: async () => {
        const chainId = (await request('eth_chainId')) as string;
        return parseInt(chainId, 16);
      },
      onAccountsChanged: () => {
      },
      onChainChanged: () => {
      },
      onDisconnect: () => {
      },
      waitForUserOperationReceipt: async (hash: Hash) => {
        return (await request('waitForUserOperationReceipt', [hash])) as UserOperationReceipt;
      },
    };

    return connector;
  });
}
