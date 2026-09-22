import type { ErrorRecord } from './errors';
import { toJson } from './format';
import type { Attribution, Payer, UserOpReceipt } from './receipt';

/**
 * The outcome ledger (design.md D7, demo-dapp spec "Outcome ledger"): every action is an entry,
 * every entry carries the evidence a bug report needs, and nothing leaves the list except by Clear or by
 * the retention cap (the oldest entries beyond LEDGER_CAP, with the eviction count kept).
 */
export type Section =
  | 'preflight'
  | 'session'
  | 'chain'
  | 'identity'
  | 'transactions'
  | 'signing'
  | 'raw-userop'
  | 'erc20'
  | 'management'
  | 'adapters'
  | 'failure-lab';

export type EntryStatus = 'pending' | 'submitted' | 'ok' | 'confirmed' | 'failed' | 'refused' | 'timed-out' | 'violation';

export type LedgerEntry = {
  id: string;
  at: string;
  section: Section;
  label: string;
  method: string;
  params?: unknown;
  chainId: number;
  chainName: string;
  walletOrigin: string;
  account?: string;
  declaredPayer?: Payer;
  status: EntryStatus;
  /** Whether a failure here was the expected outcome of a deliberate control (failure lab). */
  expected?: boolean;
  result?: unknown;
  userOpHash?: string;
  txHash?: string;
  receipt?: UserOpReceipt;
  attribution?: Attribution;
  balances?: {
    nativeBefore?: string;
    nativeAfter?: string;
    tokenBefore?: string;
    tokenAfter?: string;
    token?: string;
  };
  error?: ErrorRecord;
  /** Free-text note the demo attaches (e.g. "closed by the user or refused in the wallet"). */
  note?: string;
  durationMs?: number;
};

export type ProviderEvent = { id: string; at: string; chainId: number; event: string; payload: unknown };

export const LEDGER_CAP = 500;

export type LedgerState = { entries: LedgerEntry[]; events: ProviderEvent[]; evicted: number };

export type LedgerAction =
  | { type: 'add'; entry: LedgerEntry }
  | { type: 'update'; id: string; patch: Partial<LedgerEntry> }
  | { type: 'event'; event: ProviderEvent }
  | { type: 'clear' }
  | { type: 'hydrate'; state: LedgerState };

export function ledgerReducer(state: LedgerState, action: LedgerAction): LedgerState {
  switch (action.type) {
    case 'add': {
      const entries = [action.entry, ...state.entries];
      const evicted = Math.max(0, entries.length - LEDGER_CAP);
      return { ...state, entries: entries.slice(0, LEDGER_CAP), evicted: state.evicted + evicted };
    }
    case 'update':
      return { ...state, entries: state.entries.map((entry) => (entry.id === action.id ? { ...entry, ...action.patch } : entry)) };
    case 'event':
      return { ...state, events: [action.event, ...state.events].slice(0, LEDGER_CAP) };
    case 'clear':
      return { entries: [], events: [], evicted: 0 };
    case 'hydrate':
      return action.state;
  }
}

export const emptyLedger: LedgerState = { entries: [], events: [], evicted: 0 };

/** Namespaced per wallet origin: one dApp origin may legitimately address two tenants. */
export const ledgerStorageKey = (walletOrigin: string) => `giano-demo:ledger:${walletOrigin}`;

export function loadLedger(walletOrigin: string): LedgerState {
  try {
    const raw = localStorage.getItem(ledgerStorageKey(walletOrigin));
    if (!raw) return emptyLedger;
    // Persisted JSON is not trusted: a corrupted field must not take the ledger tab down before Clear renders.
    const parsed = JSON.parse(raw) as Partial<Record<keyof LedgerState, unknown>>;
    return {
      entries: Array.isArray(parsed.entries) ? (parsed.entries as LedgerEntry[]) : [],
      events: Array.isArray(parsed.events) ? (parsed.events as ProviderEvent[]) : [],
      evicted: typeof parsed.evicted === 'number' && Number.isFinite(parsed.evicted) ? parsed.evicted : 0,
    };
  } catch {
    return emptyLedger;
  }
}

export function saveLedger(walletOrigin: string, state: LedgerState): void {
  try {
    // Pending entries from a previous page are dead: nothing will ever settle them.
    const entries = state.entries.map((entry) => (entry.status === 'pending' || entry.status === 'submitted' ? { ...entry, status: 'timed-out' as const, note: entry.note ?? 'page unloaded before the outcome arrived' } : entry));
    localStorage.setItem(ledgerStorageKey(walletOrigin), toJson({ ...state, entries }, 0));
  } catch {
    // storage unavailable: the preflight reports it; the in-memory ledger still works
  }
}

export function newId(): string {
  return typeof crypto !== 'undefined' && 'randomUUID' in crypto ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

/** The export a bug report attaches: the entries plus everything needed to reproduce them. */
export function exportLedger(state: LedgerState, context: { config: unknown; connectorVersion: string; userAgent: string; dappOrigin: string }): string {
  return toJson({ exportedAt: new Date().toISOString(), ...context, entries: state.entries, events: state.events, evicted: state.evicted });
}
