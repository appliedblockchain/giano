import type { GianoWalletProvider } from '@appliedblockchain/giano-connector';
import { createContext, useCallback, useContext, useEffect, useMemo, useReducer, useRef, type ReactNode } from 'react';
import { CONNECTOR_VERSION, type ChainConfig, type RuntimeConfig } from '../config';
import { ChainRegistry, type ProviderOptions } from '../lib/chains';
import type { ErrorRecord } from '../lib/errors';
import type { Address } from '../lib/format';
import { emptyLedger, ledgerReducer, loadLedger, newId, saveLedger, type LedgerAction, type LedgerEntry, type LedgerState, type Section } from '../lib/ledger';
import { runPreflight, type PreflightResult } from '../lib/preflight';
import { runAction, type ActionApi, type ActionSpec, type RunOutcome } from '../lib/run';

/**
 * One store for the page: the ledger, the per-chain sessions, the selected chain, the invariant
 * violations, the preflight result and the reconnect prompt. Cards read from it and act through
 * `run()`; nothing else writes to the ledger.
 */
export type Session = {
  account?: Address;
  /** The chain the wallet GRANTED in the handshake, as `eth_chainId` returns it. */
  grantedChainId?: string;
  supportedChainIds: readonly number[];
  connectedAt?: string;
};

export type Violation = { id: string; at: string; title: string; detail: string };

type State = {
  ledger: LedgerState;
  sessions: Record<number, Session>;
  selectedChainId: number;
  violations: Violation[];
  preflight?: PreflightResult;
  preflightRunning: boolean;
  reconnectPrompt?: { chainId: number; at: string; error: ErrorRecord };
  /** Bumped when the registry changes shape (ad-hoc chain, provider options) so lists re-render. */
  registryVersion: number;
};

type Action =
  | { type: 'ledger'; action: LedgerAction }
  | { type: 'session'; chainId: number; session: Partial<Session> }
  | { type: 'clear-session'; chainId: number }
  | { type: 'select'; chainId: number }
  | { type: 'violation'; violation: Violation }
  | { type: 'dismiss-violation'; id: string }
  | { type: 'preflight-start' }
  | { type: 'preflight'; result: PreflightResult }
  | { type: 'reconnect-prompt'; prompt: State['reconnectPrompt'] }
  | { type: 'registry-changed' };

function reducer(state: State, action: Action): State {
  switch (action.type) {
    case 'ledger':
      return { ...state, ledger: ledgerReducer(state.ledger, action.action) };
    case 'session': {
      const base: Session = state.sessions[action.chainId] ?? { supportedChainIds: [] };
      return { ...state, sessions: { ...state.sessions, [action.chainId]: { ...base, ...action.session } } };
    }
    case 'clear-session': {
      const sessions = { ...state.sessions };
      delete sessions[action.chainId];
      return { ...state, sessions };
    }
    case 'select':
      return { ...state, selectedChainId: action.chainId };
    case 'violation':
      return { ...state, violations: [action.violation, ...state.violations] };
    case 'dismiss-violation':
      return { ...state, violations: state.violations.filter((violation) => violation.id !== action.id) };
    case 'preflight-start':
      return { ...state, preflightRunning: true };
    case 'preflight':
      return { ...state, preflight: action.result, preflightRunning: false };
    case 'reconnect-prompt':
      return { ...state, reconnectPrompt: action.prompt };
    case 'registry-changed':
      return { ...state, registryVersion: state.registryVersion + 1 };
  }
}

export type Demo = {
  config: RuntimeConfig;
  registry: ChainRegistry;
  state: State;
  selected: { config: ChainConfig; chainId: number };
  /** The account granted on the selected chain, if any. */
  account?: Address;
  /** The first account any chain granted: the reference for the identity invariant. */
  referenceAccount?: Address;
  run: <T>(spec: Omit<ActionSpec, 'chainId'> & { chainId?: number }, fn: (api: ActionApi) => Promise<T>) => Promise<RunOutcome<T>>;
  selectChain: (chainId: number) => void;
  connect: (chainId?: number) => Promise<RunOutcome<string[]>>;
  disconnect: (chainId?: number) => Promise<void>;
  revoke: (chainId?: number) => Promise<void>;
  addAdHocChain: (chainId: number, rpcUrl: string, name?: string, options?: { select?: boolean }) => void;
  setProviderOptions: (chainId: number, options: ProviderOptions) => void;
  recordViolation: (section: Section, title: string, detail: string, chainId?: number) => void;
  dismissViolation: (id: string) => void;
  rerunPreflight: () => Promise<void>;
  clearReconnectPrompt: () => void;
  clearLedger: () => void;
  ledgerDispatch: (action: LedgerAction) => void;
  isChainDisabled: (chainId: number) => boolean;
};

const DemoContext = createContext<Demo | null>(null);

export function DemoProvider({ config, children }: { config: RuntimeConfig; children: ReactNode }) {
  const registryRef = useRef<ChainRegistry | null>(null);
  if (!registryRef.current) registryRef.current = new ChainRegistry(config.walletUrl, config.chains);
  const registry = registryRef.current;

  const [state, dispatch] = useReducer(reducer, undefined, (): State => ({
    ledger: typeof localStorage !== 'undefined' ? loadLedger(registry.walletOrigin) : emptyLedger,
    sessions: {},
    selectedChainId: config.chains[0].chainId,
    violations: [],
    preflightRunning: false,
    registryVersion: 0,
  }));

  const ledgerDispatch = useCallback((action: LedgerAction) => dispatch({ type: 'ledger', action }), []);

  // Persist the ledger (design.md D7). Namespaced by wallet origin; capped in the reducer.
  useEffect(() => {
    saveLedger(registry.walletOrigin, state.ledger);
  }, [registry, state.ledger]);

  // Subscribe to every provider the registry builds: events go to the events log, accounts to sessions.
  useEffect(() => {
    return registry.onProvider((chainId: number, provider: GianoWalletProvider) => {
      const record = (event: string) => (payload: unknown) => {
        ledgerDispatch({ type: 'event', event: { id: newId(), at: new Date().toISOString(), chainId, event, payload } });
        if (event === 'accountsChanged') {
          const accounts = payload as string[];
          if (accounts?.length) dispatch({ type: 'session', chainId, session: { account: accounts[0] as Address } });
          else dispatch({ type: 'clear-session', chainId });
        }
        if (event === 'disconnect') {
          const error = payload as { code?: number; message?: string } | undefined;
          dispatch({ type: 'clear-session', chainId });
          if (error && typeof error === 'object' && 'code' in error && error.code === 4900) {
            dispatch({ type: 'reconnect-prompt', prompt: { chainId, at: new Date().toISOString(), error: { name: 'disconnect', code: 4900, message: error.message ?? 'session ended by the wallet' } } });
          }
        }
      };
      for (const event of ['connect', 'accountsChanged', 'chainChanged', 'disconnect']) provider.on(event, record(event));
    });
  }, [registry, ledgerDispatch]);

  // Session resume: eth_accounts answers from the cached session without a popup.
  useEffect(() => {
    for (const chain of config.chains) {
      const provider = registry.providerFor(chain.chainId);
      if (!provider.isConnected()) continue;
      void provider
        .request<string[]>({ method: 'eth_accounts' })
        .then(async (accounts) => {
          if (!accounts?.length) return;
          const grantedChainId = await provider.request<string>({ method: 'eth_chainId' }).catch(() => undefined);
          dispatch({ type: 'session', chainId: chain.chainId, session: { account: accounts[0] as Address, grantedChainId, supportedChainIds: provider.supportedChainIds } });
          ledgerDispatch({
            type: 'add',
            entry: {
              id: newId(),
              at: new Date().toISOString(),
              section: 'session',
              label: 'Session resumed from cache',
              method: 'eth_accounts',
              chainId: chain.chainId,
              chainName: chain.name,
              walletOrigin: registry.walletOrigin,
              account: accounts[0] as Address,
              status: 'ok',
              result: accounts,
              note: 'answered without a popup',
            },
          });
        })
        .catch(() => undefined);
    }
  }, [config.chains, registry, ledgerDispatch]);

  const rerunPreflight = useCallback(async () => {
    dispatch({ type: 'preflight-start' });
    const result = await runPreflight(config, registry, CONNECTOR_VERSION);
    dispatch({ type: 'preflight', result });
    console.info('[giano-demo] preflight', result);
  }, [config, registry]);

  useEffect(() => {
    void rerunPreflight();
  }, [rerunPreflight]);

  const run = useCallback<Demo['run']>(
    (spec, fn) =>
      runAction(
        {
          registry,
          ledger: ledgerDispatch,
          onSessionEnded: (chainId, error) => {
            dispatch({ type: 'clear-session', chainId });
            dispatch({ type: 'reconnect-prompt', prompt: { chainId, at: new Date().toISOString(), error } });
          },
        },
        { ...spec, chainId: spec.chainId ?? state.selectedChainId },
        fn,
      ),
    [registry, ledgerDispatch, state.selectedChainId],
  );

  const referenceAccount = useMemo(() => {
    const ordered = Object.values(state.sessions)
      .filter((session) => session.account && session.connectedAt)
      .sort((a, b) => (a.connectedAt! < b.connectedAt! ? -1 : 1));
    return ordered[0]?.account ?? Object.values(state.sessions).find((session) => session.account)?.account;
  }, [state.sessions]);

  const recordViolation = useCallback<Demo['recordViolation']>(
    (section, title, detail, chainId) => {
      const id = newId();
      const at = new Date().toISOString();
      dispatch({ type: 'violation', violation: { id, at, title, detail } });
      const chain = registry.get(chainId ?? state.selectedChainId)?.config;
      ledgerDispatch({
        type: 'add',
        entry: { id, at, section, label: title, method: 'invariant', chainId: chain?.chainId ?? 0, chainName: chain?.name ?? '—', walletOrigin: registry.walletOrigin, status: 'violation', note: detail },
      });
      console.error(`[giano-demo] VIOLATION: ${title} — ${detail}`);
    },
    [registry, ledgerDispatch, state.selectedChainId],
  );

  const connect = useCallback<Demo['connect']>(
    async (chainId = state.selectedChainId) => {
      const outcome = await run({ section: 'session', label: `Connect on ${registry.require(chainId).config.name}`, method: 'eth_requestAccounts', chainId, noBalances: true }, async (api) => {
        const accounts = await api.provider.request<string[]>({ method: 'eth_requestAccounts' });
        const grantedChainId = await api.provider.request<string>({ method: 'eth_chainId' });
        api.update({ result: { accounts, grantedChainId, supportedChainIds: api.provider.supportedChainIds }, account: accounts[0] as Address });
        dispatch({ type: 'session', chainId, session: { account: accounts[0] as Address, grantedChainId, supportedChainIds: api.provider.supportedChainIds, connectedAt: new Date().toISOString() } });
        if (Number.parseInt(grantedChainId, 16) !== chainId) {
          recordViolation('chain', 'Granted chain differs from the configured chain', `provider for ${chainId} reports eth_chainId ${grantedChainId}`, chainId);
        }
        return accounts;
      });
      return outcome;
    },
    [run, registry, state.selectedChainId, recordViolation],
  );

  const disconnect = useCallback<Demo['disconnect']>(
    async (chainId = state.selectedChainId) => {
      await run({ section: 'session', label: `Disconnect on ${registry.require(chainId).config.name}`, method: 'disconnect()', chainId, noBalances: true }, async (api) => {
        api.provider.disconnect();
        dispatch({ type: 'clear-session', chainId });
        return 'disconnected';
      });
    },
    [run, registry, state.selectedChainId],
  );

  const revoke = useCallback<Demo['revoke']>(
    async (chainId = state.selectedChainId) => {
      await run({ section: 'session', label: 'Revoke permissions, then read eth_accounts', method: 'wallet_revokePermissions', chainId, noBalances: true }, async (api) => {
        await api.provider.request({ method: 'wallet_revokePermissions', params: [{ eth_accounts: {} }] });
        dispatch({ type: 'clear-session', chainId });
        const accounts = await api.provider.request<string[]>({ method: 'eth_accounts' });
        api.update({ result: { afterRevoke: { eth_accounts: accounts } } });
        if (accounts.length) recordViolation('failure-lab', 'eth_accounts still answers after wallet_revokePermissions', JSON.stringify(accounts), chainId);
        return accounts;
      });
    },
    [run, state.selectedChainId, recordViolation],
  );

  const value = useMemo<Demo>(() => {
    const selectedEntry = registry.get(state.selectedChainId) ?? registry.list()[0];
    return {
      config,
      registry,
      state,
      selected: { config: selectedEntry.config, chainId: selectedEntry.config.chainId },
      account: state.sessions[selectedEntry.config.chainId]?.account,
      referenceAccount,
      run,
      selectChain: (chainId) => dispatch({ type: 'select', chainId }),
      connect,
      disconnect,
      revoke,
      addAdHocChain: (chainId, rpcUrl, name, options) => {
        registry.addAdHocChain(chainId, rpcUrl, name);
        dispatch({ type: 'registry-changed' });
        // The Chain card selects what the user just added; the failure lab must not move the selection.
        if (options?.select !== false) dispatch({ type: 'select', chainId });
      },
      setProviderOptions: (chainId, options) => {
        registry.setOptions(chainId, options);
        dispatch({ type: 'clear-session', chainId });
        dispatch({ type: 'registry-changed' });
      },
      recordViolation,
      dismissViolation: (id) => dispatch({ type: 'dismiss-violation', id }),
      rerunPreflight,
      clearReconnectPrompt: () => dispatch({ type: 'reconnect-prompt', prompt: undefined }),
      clearLedger: () => ledgerDispatch({ type: 'clear' }),
      ledgerDispatch,
      isChainDisabled: (chainId) => state.preflight?.wrongNetworkChainIds.includes(chainId) ?? false,
    };
  }, [config, registry, state, referenceAccount, run, connect, disconnect, revoke, recordViolation, rerunPreflight, ledgerDispatch]);

  return <DemoContext.Provider value={value}>{children}</DemoContext.Provider>;
}

export function useDemo(): Demo {
  const demo = useContext(DemoContext);
  if (!demo) throw new Error('useDemo must be used inside DemoProvider');
  return demo;
}

/**
 * How many ledger entries have SETTLED (a receipt, a result or an error). Balances refresh on this,
 * not on the entry count: an entry is added at submission, but the balance only moves at the receipt.
 */
export function useSettledCount(): number {
  const { state } = useDemo();
  return useMemo(() => state.ledger.entries.filter((entry) => entry.status !== 'pending' && entry.status !== 'submitted').length, [state.ledger.entries]);
}

/** The latest ledger entry for a section: what each card shows inline. */
export function useSectionEntries(section: Section, limit = 3): LedgerEntry[] {
  const { state } = useDemo();
  return useMemo(() => state.ledger.entries.filter((entry) => entry.section === section).slice(0, limit), [state.ledger.entries, section, limit]);
}
