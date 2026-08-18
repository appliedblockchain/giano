import { RPC_ERRORS, TransportClient, TransportError, TransportRpcError } from '@appliedblockchain/giano-wallet-transport';
import type { Chain, EIP1193Parameters, Transport } from 'viem';
import { createPublicClient, http } from 'viem';

export type CreateGianoWalletProviderParams = {
  /** URL of the wallet-web deployment (e.g. https://wallet.clientapp.com). */
  walletUrl: string;
  chain: Chain;
  /** Read-path transport (eth_call & co. are answered dApp-side, no popup). */
  transport?: Transport;
  /** Path prefix under the wallet origin that proxies to the wallet-api (nginx default). */
  walletApiPath?: string;
  /** Persistence for session resume; defaults to localStorage. */
  storage?: Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;
  sdkVersion?: string;
};

export type GianoWalletProvider = {
  request: <T = unknown>(args: EIP1193Parameters | { method: string; params?: unknown }) => Promise<T>;
  on: (event: string, listener: (payload: unknown) => void) => GianoWalletProvider;
  removeListener: (event: string, listener: (payload: unknown) => void) => GianoWalletProvider;
  /** True once a wallet session is cached (answers eth_accounts without a popup). */
  isConnected: () => boolean;
  disconnect: () => void;
};

/** Methods that always go to the wallet popup (user action / signing / credentials). */
const WALLET_METHODS = new Set([
  'eth_requestAccounts',
  'eth_sendTransaction',
  'personal_sign',
  'eth_sign',
  'eth_signTypedData_v4',
  'eth_prepareUserOperation',
  'eth_signUserOperation',
  'eth_sendSignedUserOperation',
  'signed_eth_call',
]);

/** Pre-namespacing cache key — migrated to the per-wallet key on first read. */
const LEGACY_STORAGE_KEY = 'giano:sdk:session';

type CachedSession = { accounts: string[]; chainId: string };

/**
 * The thin Giano SDK provider: all wallet trust (passkeys, signing, consent) lives on
 * the wallet origin; the dApp bundle contains no WebAuthn, credential or bundler code.
 *
 * - reads (`eth_call`, `eth_chainId`, …) are answered locally over `transport`
 * - `eth_accounts` answers from the cached session without opening a popup
 * - wallet methods open the popup transport (call from a user gesture)
 * - `waitForUserOperationReceipt` polls the wallet-api's public receipt endpoint —
 *   dApps never need a bundler URL
 */
export function createGianoWalletProvider(params: CreateGianoWalletProviderParams): GianoWalletProvider {
  const { walletUrl, chain, sdkVersion = '1.0.0', walletApiPath = '/api' } = params;
  const walletOrigin = new URL(walletUrl).origin;
  // Namespaced per wallet origin + chain: one dApp origin may legitimately address two
  // wallet origins (two tenants), and an unnamespaced key would cross-answer eth_accounts.
  const storageKey = `giano:sdk:session:${walletOrigin}:${chain.id}`;
  const storage = params.storage ?? (typeof localStorage !== 'undefined' ? localStorage : undefined);

  const publicClient = createPublicClient({
    chain,
    transport: params.transport ?? http(chain.rpcUrls.default.http[0]),
  });

  const listeners = new Map<string, Set<(payload: unknown) => void>>();
  const emit = (event: string, payload: unknown) => listeners.get(event)?.forEach((listener) => listener(payload));

  const readSession = (): CachedSession | null => {
    try {
      let raw = storage?.getItem(storageKey);
      if (!raw) {
        // one-time migration from the pre-namespacing key
        const legacy = storage?.getItem(LEGACY_STORAGE_KEY);
        if (legacy) {
          storage?.setItem(storageKey, legacy);
          storage?.removeItem(LEGACY_STORAGE_KEY);
          raw = legacy;
        }
      }
      return raw ? (JSON.parse(raw) as CachedSession) : null;
    } catch {
      return null;
    }
  };
  const writeSession = (session: CachedSession | null) => {
    if (!storage) return;
    if (session) storage.setItem(storageKey, JSON.stringify(session));
    else storage.removeItem(storageKey);
  };

  const transportClient = new TransportClient({ walletUrl, sdkVersion });

  transportClient.on('accountsChanged', (accounts) => {
    const session = readSession();
    if (session && Array.isArray(accounts)) writeSession({ ...session, accounts: accounts as string[] });
    emit('accountsChanged', accounts);
  });
  transportClient.on('chainChanged', (chainId) => emit('chainChanged', chainId));

  /** Drops the cached session and notifies the dApp that a fresh connect is required. */
  const clearSession = (error: unknown) => {
    writeSession(null);
    emit('accountsChanged', []);
    emit('disconnect', error);
  };

  transportClient.on('disconnect', (error) => {
    // A transient popup close is NOT a session end: the wallet keeps its session and the
    // next wallet request silently restores the account (see giano_restoreAccount), so we
    // keep the cached session and stay quiet. Only a genuine end (explicit disconnect or
    // the wallet closing the session) drops the cache.
    if (error instanceof TransportError && error.code === 'POPUP_CLOSED') return;
    clearSession(error);
  });

  const requestViaWallet = async <T>(method: string, requestParams: unknown): Promise<T> => {
    if (!transportClient.isConnected) {
      await transportClient.connect();
    }
    try {
      return await transportClient.request<T>(method, requestParams);
    } catch (error) {
      // The wallet couldn't restore the account (e.g. the persisted session expired):
      // our cached session is stale, so drop it and surface a clean disconnect. The dApp
      // should reconnect via eth_requestAccounts.
      if (error instanceof TransportRpcError && error.code === RPC_ERRORS.DISCONNECTED) {
        clearSession(error);
      }
      throw error;
    }
  };

  const waitForUserOperationReceipt = async ([hash]: [string]): Promise<unknown> => {
    const url = `${walletOrigin}${walletApiPath}/v1/userops/${hash}/receipt`;
    const deadline = Date.now() + 120_000;
    while (Date.now() < deadline) {
      const response = await fetch(url);
      if (response.ok) {
        const { receipt } = (await response.json()) as { receipt: unknown };
        if (receipt) return receipt;
      }
      await new Promise((resolve) => setTimeout(resolve, 2_000));
    }
    throw new TransportError('REQUEST_TIMEOUT', `no receipt for ${hash} within 120s`);
  };

  const provider: GianoWalletProvider = {
    isConnected: () => readSession() !== null,

    disconnect: () => {
      // When the transport is live, its teardown fires the 'disconnect' handler above,
      // which clears the session and emits. Only emit here for the not-connected case so
      // an explicit disconnect() still notifies the dApp exactly once.
      const wasConnected = transportClient.isConnected;
      transportClient.disconnect();
      if (!wasConnected) {
        clearSession({ code: RPC_ERRORS.DISCONNECTED, message: 'disconnected' });
      }
    },

    request: async <T>(args: { method: string; params?: unknown }): Promise<T> => {
      const { method, params: requestParams } = args;

      switch (method) {
        case 'eth_accounts': {
          return (readSession()?.accounts ?? []) as T;
        }
        case 'eth_chainId': {
          return (readSession()?.chainId ?? `0x${chain.id.toString(16)}`) as T;
        }
        case 'eth_requestAccounts': {
          try {
            const accounts = await requestViaWallet<string[]>(method, requestParams);
            const chainId = await requestViaWallet<string>('eth_chainId', undefined).catch(() => `0x${chain.id.toString(16)}`);
            writeSession({ accounts, chainId });
            emit('connect', { chainId });
            emit('accountsChanged', accounts);
            return accounts as T;
          } finally {
            // Ephemeral popup: close it once the connect ceremony resolves. Later actions
            // re-open a fresh popup and the wallet silently restores the account.
            transportClient.dismissPopup();
          }
        }
        case 'wallet_revokePermissions': {
          provider.disconnect();
          return null as T;
        }
        case 'waitForUserOperationReceipt': {
          return waitForUserOperationReceipt(requestParams as [string]) as Promise<T>;
        }
        default: {
          if (WALLET_METHODS.has(method)) {
            try {
              return await requestViaWallet<T>(method, requestParams);
            } finally {
              // Ephemeral popup: close it once this signing/transaction request settles.
              transportClient.dismissPopup();
            }
          }
          // read path: answered dApp-side without touching the popup
          return publicClient.request({ method, params: requestParams } as never) as Promise<T>;
        }
      }
    },

    on: (event, listener) => {
      if (!listeners.has(event)) listeners.set(event, new Set());
      listeners.get(event)!.add(listener);
      return provider;
    },

    removeListener: (event, listener) => {
      listeners.get(event)?.delete(listener);
      return provider;
    },
  };

  return provider;
}
