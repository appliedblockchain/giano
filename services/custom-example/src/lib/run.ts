import type { GianoWalletProvider } from '@appliedblockchain/giano-connector';
import { erc20Abi } from 'viem';
import type { ChainEntry, ChainRegistry } from './chains';
import { describeError, isSessionEnded, type ErrorRecord } from './errors';
import type { Address } from './format';
import { newId, type LedgerAction, type LedgerEntry, type Section } from './ledger';
import { attributePayer, type Payer, type UserOpReceipt } from './receipt';

/**
 * Every user action goes through `runAction` (design.md D7): it opens a ledger entry, captures the
 * balances before, runs the action, captures the balances after, attributes the payer from the receipt
 * when there is one, records the typed error when there is not, and closes the entry with a duration.
 * Cards never write to the ledger directly.
 */
export type RunContext = {
  registry: ChainRegistry;
  ledger: (action: LedgerAction) => void;
  /** Called when the wallet ended the session (4900): the header raises a reconnect prompt. */
  onSessionEnded?: (chainId: number, error: ErrorRecord) => void;
};

export type ActionSpec = {
  section: Section;
  label: string;
  method: string;
  params?: unknown;
  chainId: number;
  account?: Address;
  declaredPayer?: Payer;
  /** Track this token's balance for the account across the action. */
  token?: Address;
  /** A deliberate failure control: a failure is the expected outcome and is recorded as `refused`. */
  expected?: boolean;
  /** A 4001 after a sponsored send is ambiguous (finding G5); annotate it. */
  sponsoredSend?: boolean;
  /** Skip balance captures (signing, reads). */
  noBalances?: boolean;
};

export type ActionApi = {
  id: string;
  entry: ChainEntry;
  provider: GianoWalletProvider;
  /** Mid-action patch: submitted hash, receipt, status. */
  update: (patch: Partial<LedgerEntry>) => void;
};

export type RunOutcome<T> = { id: string; result?: T; error?: ErrorRecord; entry: LedgerEntry };

async function readBalances(entry: ChainEntry, account: Address | undefined, token: Address | undefined): Promise<{ native?: bigint; token?: bigint }> {
  if (!account) return {};
  const [native, tokenBalance] = await Promise.all([
    entry.publicClient.getBalance({ address: account }).catch(() => undefined),
    token ? entry.publicClient.readContract({ address: token, abi: erc20Abi, functionName: 'balanceOf', args: [account] }).catch(() => undefined) : Promise.resolve(undefined),
  ]);
  return { native, token: tokenBalance };
}

export async function runAction<T>(ctx: RunContext, spec: ActionSpec, fn: (api: ActionApi) => Promise<T>): Promise<RunOutcome<T>> {
  const entry = ctx.registry.require(spec.chainId);
  const id = newId();
  const started = Date.now();
  let current: LedgerEntry = {
    id,
    at: new Date().toISOString(),
    section: spec.section,
    label: spec.label,
    method: spec.method,
    params: spec.params,
    chainId: spec.chainId,
    chainName: entry.config.name,
    walletOrigin: ctx.registry.walletOrigin,
    account: spec.account,
    declaredPayer: spec.declaredPayer,
    status: 'pending',
    expected: spec.expected,
    balances: spec.token ? { token: spec.token } : undefined,
  };
  const patch = (p: Partial<LedgerEntry>) => {
    current = { ...current, ...p };
    ctx.ledger({ type: 'update', id, patch: p });
  };
  ctx.ledger({ type: 'add', entry: current });
  console.info(`[giano-demo] ${spec.section}/${spec.method} on ${entry.config.name}`, spec.params);

  const before = spec.noBalances ? {} : await readBalances(entry, spec.account, spec.token);
  if (before.native !== undefined || before.token !== undefined) {
    patch({ balances: { ...current.balances, nativeBefore: before.native?.toString(), tokenBefore: before.token?.toString() } });
  }

  let result: T | undefined;
  let error: ErrorRecord | undefined;
  try {
    result = await fn({ id, entry, provider: ctx.registry.providerFor(spec.chainId), update: patch });
    const receipt = current.receipt;
    const status = current.status === 'pending' || current.status === 'submitted' ? (receipt ? (receipt.success === false ? 'failed' : 'confirmed') : 'ok') : current.status;
    patch({ status, result: current.result ?? (result as unknown) });
  } catch (raw) {
    error = describeError(raw, { sponsoredSend: spec.sponsoredSend });
    console.error(`[giano-demo] ${spec.section}/${spec.method} failed`, raw);
    const timedOut = error.name === 'TransportError' && error.code === 'REQUEST_TIMEOUT';
    patch({ status: timedOut ? 'timed-out' : spec.expected ? 'refused' : 'failed', error });
    if (isSessionEnded(raw)) ctx.onSessionEnded?.(spec.chainId, error);
  }

  if (!spec.noBalances && spec.account) {
    const after = await readBalances(entry, spec.account, spec.token);
    const balances = { ...current.balances, nativeAfter: after.native?.toString(), tokenAfter: after.token?.toString() };
    const attribution = current.receipt ? attributePayer(current.receipt, spec.declaredPayer, before.native, after.native) : undefined;
    patch({ balances, attribution, ...(attribution?.matchesDeclared === false ? { note: 'payer differs from declaration' } : {}) });
  }
  patch({ durationMs: Date.now() - started });
  return { id, result, error, entry: current };
}

export type TxRequest = { to: Address; value?: `0x${string}`; data?: `0x${string}` };

/**
 * eth_sendTransaction → userOp hash (recorded immediately) → waitForUserOperationReceipt → receipt.
 * The connector returns the receipt untyped (finding G4); it is the bundler's receipt shape.
 */
export async function submitTransaction(api: ActionApi, tx: TxRequest): Promise<UserOpReceipt> {
  const hash = await api.provider.request<string>({ method: 'eth_sendTransaction', params: [tx] });
  api.update({ userOpHash: hash, status: 'submitted' });
  return waitForReceipt(api, hash);
}

export async function waitForReceipt(api: ActionApi, hash: string): Promise<UserOpReceipt> {
  const receipt = await api.provider.request<UserOpReceipt>({ method: 'waitForUserOperationReceipt', params: [hash] });
  api.update({ receipt, txHash: receipt?.receipt?.transactionHash, result: receipt });
  return receipt;
}
