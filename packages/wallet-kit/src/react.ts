/**
 * The React adapter (WK-23, D2): thin hooks over the framework-free core, behind its own
 * entry point (`@appliedblockchain/giano-wallet-kit/react`). It adds no capability the
 * core lacks — it only wraps the core's subscriptions as idiomatic React state.
 */
import { createContext, createElement, useContext, useEffect, useMemo, useState, useSyncExternalStore, type ReactNode } from 'react';
import type { WalletConfig } from './config';
import { createWalletHost, type WalletHost } from './host';
import { createManagementController, type ManagementController, type ManagementFlow, type ManagementState } from './management/controller';
import type { PendingRequest } from './requests';
import { createWalletRuntimes, type WalletRuntimes } from './runtimes';

export type WalletKitContextValue = {
  config: WalletConfig;
  runtimes: WalletRuntimes;
  host: WalletHost;
};

const WalletKitContext = createContext<WalletKitContextValue | null>(null);

export type WalletHostProviderProps = {
  config: WalletConfig;
  walletVersion: string;
  children: ReactNode;
};

/**
 * Builds the runtimes and the host once, starts the transport for the component's
 * lifetime, and makes them available to the hooks below.
 */
export function WalletHostProvider({ config, walletVersion, children }: WalletHostProviderProps) {
  const runtimes = useMemo(() => createWalletRuntimes(config), [config]);
  const host = useMemo(() => createWalletHost({ runtimes, config, walletVersion }), [runtimes, config, walletVersion]);

  useEffect(() => {
    host.start();
    return () => host.stop();
  }, [host]);

  return createElement(WalletKitContext.Provider, { value: { config, runtimes, host } }, children);
}

export function useWalletKit(): WalletKitContextValue {
  const context = useContext(WalletKitContext);
  if (!context) throw new Error('useWalletKit must be used inside <WalletHostProvider>');
  return context;
}

/** The single-slot pending request (WK-10), re-rendered on every change. */
export function usePendingRequest(): PendingRequest | null {
  const { host } = useWalletKit();
  return useSyncExternalStore(
    (onStoreChange) => host.requests.subscribe(onStoreChange),
    () => host.requests.current,
  );
}

export type UseManagementResult = {
  state: ManagementState;
  flow: ManagementFlow | null;
  actions: ManagementController;
};

/**
 * Mounts a management controller for the component's lifetime; `load()` runs on mount.
 * Returns the controller's state and flow (re-rendered on change) and its actions.
 */
export function useManagement(): UseManagementResult {
  const { config, runtimes } = useWalletKit();
  const controller = useMemo(() => createManagementController({ runtimes, config }), [runtimes, config]);
  const [state, setState] = useState<ManagementState>(controller.state);

  useEffect(() => {
    const unsubscribe = controller.subscribe(setState);
    void controller.load();
    return () => {
      unsubscribe();
      controller.destroy();
    };
  }, [controller]);

  return { state, flow: controller.flow, actions: controller };
}
