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
 * Structural provider surface the connector needs — satisfied by the provider returned
 * from `createGianoWalletProvider`.
 */
export type GianoProviderLike = {
  request: (args: { method: string; params?: unknown }) => Promise<unknown>;
  on: (event: never, listener: never) => unknown;
  removeListener: (event: never, listener: never) => unknown;
};

export type CreateGianoConnectorParams = {
  provider: GianoProviderLike | GianoWalletProvider;
};

/**
 * Thrown by the wagmi adapter's `switchChain`: Giano binds one chain per provider instance
 * (MC-01), so switching is refused with a typed error rather than left to fail obscurely
 * deeper in the stack (MC-15). wagmi's `useSwitchChain` surfaces this to the UI.
 */
export class UnsupportedChainSwitchError extends Error {
  constructor(public readonly requestedChainId: number) {
    super(
      'Giano binds one chain per connector instance. Create a connector over a provider constructed for the target chain.',
    );
    this.name = 'UnsupportedChainSwitchError';
  }
}

type GianoConnectorProperties = {
  waitForUserOperationReceipt: (hash: Hash) => Promise<UserOperationReceipt>;
}

export function createGianoConnector({ provider }: CreateGianoConnectorParams) {
  return createConnector<
    GianoProviderLike,
    GianoConnectorProperties
  >(() => {
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
        // Throwing rather than removing the method: wagmi's useSwitchChain surfaces a thrown
        // error to the UI, whereas an absent method produces a less legible failure (MC-15).
        throw new UnsupportedChainSwitchError(chainId);
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
