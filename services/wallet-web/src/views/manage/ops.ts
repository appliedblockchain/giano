import type { Hex } from 'viem';
import type { SponsorshipPreflight, WalletRuntime, WalletRuntimes } from '../../wallet';

/**
 * Applies one owner change to every served chain, as ordinary consented UserOperations
 * (D4): a self-call, sponsored under the platform wallet-management rule, relayed and
 * audited like any other transaction.
 *
 * Chain-bound, one operation per chain (WM-42). The chain-independent single-signature
 * path (WM-41) is NOT used: the deployment's sponsorship authorisations are EIP-712
 * chain-bound and the relay only admits decodable execute/executeBatch calls, so a
 * replayable `executeWithoutChainIdValidation` operation could neither be sponsored nor
 * relayed today — see the implementation report. Each chain therefore takes its own
 * passkey signature, sequentially, with per-chain progress (WM-44).
 *
 * A chain where the account is not yet deployed is SKIPPED with a statement (WM-46, Q2):
 * deploying every served chain to add a backup credential is real gas for chains the user
 * may never touch; the divergence stays visible in the owner list (WM-06).
 */

export type ChainStepState = 'waiting' | 'checking' | 'skipped' | 'refused' | 'submitted' | 'confirmed' | 'failed';

export type ChainProgress = {
  chainId: number;
  chainName: string;
  state: ChainStepState;
  detail?: string;
  userOpHash?: string;
};

export type OwnerChangeOutcome = {
  /** True when every chain that was not skipped confirmed. */
  ok: boolean;
  /** Set when a sponsorship refusal aborted the run — shown with the WM-48/WM-49 copy. */
  refusal?: Extract<SponsorshipPreflight, { state: 'refused' }>;
  progress: ChainProgress[];
  /** The chains the change actually confirmed on. */
  appliedChainIds: number[];
};

export type ApplyOwnerChangeOptions = {
  runtimes: WalletRuntimes;
  walletAddress: Hex;
  /** For the console record (D10). */
  label: string;
  /**
   * Builds the self-call data for ONE chain, immediately before submission — removal
   * re-reads the owner's index here, because a stale index is a failed transaction
   * (WM-29). Returning null skips the chain (e.g. the owner is not present there).
   */
  buildData: (runtime: WalletRuntime) => Promise<Hex | null>;
  onProgress: (progress: ChainProgress[]) => void;
};

const log = (label: string, data: unknown) => console.log(`[giano-wallet:manage] ${label}`, data);

/** Restores the in-memory account from the persisted session — no passkey prompt. */
async function ensureAccount(runtime: WalletRuntime): Promise<boolean> {
  if (runtime.provider.getSmartAccount()) return true;
  await runtime.provider.request({ method: 'giano_restoreAccount', params: [] }).catch(() => undefined);
  return !!runtime.provider.getSmartAccount();
}

export async function applyOwnerChange(options: ApplyOwnerChangeOptions): Promise<OwnerChangeOutcome> {
  const { runtimes, walletAddress, label, buildData, onProgress } = options;

  const progress: ChainProgress[] = runtimes.servedChainIds.map((chainId) => ({
    chainId,
    chainName: runtimes.descriptorFor(chainId).name,
    state: 'waiting',
  }));
  const update = (chainId: number, patch: Partial<ChainProgress>) => {
    const row = progress.find((entry) => entry.chainId === chainId)!;
    Object.assign(row, patch);
    onProgress([...progress]);
  };

  let refusal: OwnerChangeOutcome['refusal'];
  const appliedChainIds: number[] = [];

  for (const chainId of runtimes.servedChainIds) {
    const runtime = runtimes.runtimeFor(chainId);
    update(chainId, { state: 'checking' });

    // A refusal on an earlier chain is tenant-level (the platform rule and the tenant's
    // switch are not per-chain concepts the user can act on differently) — stop asking.
    if (refusal) {
      update(chainId, { state: 'refused', detail: 'not attempted — sponsorship was refused' });
      continue;
    }

    try {
      if (!(await ensureAccount(runtime))) {
        update(chainId, { state: 'failed', detail: 'no signed-in account for this chain' });
        continue;
      }

      // WM-46/Q2: never attempted on a chain where the account is not deployed — stated,
      // not hidden. The chain reconciles when the account first deploys there.
      if (!(await runtime.isAccountDeployed(walletAddress))) {
        update(chainId, { state: 'skipped', detail: 'the account is not deployed on this chain yet — the change is not applied here' });
        continue;
      }

      const data = await buildData(runtime);
      if (data === null) {
        update(chainId, { state: 'skipped', detail: 'nothing to change on this chain' });
        continue;
      }

      // Pre-flight BEFORE the passkey prompt (WM-68): a refused operation must never cost
      // the user a ceremony that could not have succeeded.
      const preflight = await runtime.checkSponsorship({ to: walletAddress, data });
      if (preflight.state === 'refused') {
        refusal = preflight;
        update(chainId, { state: 'refused', detail: preflight.message });
        log(`${label}: sponsorship refused`, { chainId, reason: preflight.reason, message: preflight.message });
        continue;
      }
      if (preflight.state === 'unavailable') {
        update(chainId, { state: 'failed', detail: `sponsorship temporarily unavailable: ${preflight.message}` });
        log(`${label}: sponsorship unavailable`, { chainId, message: preflight.message });
        continue;
      }

      const userOpHash = await runtime.provider.request({
        method: 'eth_sendTransaction',
        params: [{ to: walletAddress, value: '0x0', data } as never],
      });
      update(chainId, { state: 'submitted', userOpHash: userOpHash as string });
      log(`${label}: submitted`, { chainId, userOpHash });

      const receipt = (await runtime.provider.request({
        method: 'waitForUserOperationReceipt',
        params: [userOpHash as `0x${string}`],
      })) as { success: boolean };
      if (receipt.success) {
        appliedChainIds.push(chainId);
        update(chainId, { state: 'confirmed', userOpHash: userOpHash as string });
        log(`${label}: confirmed`, { chainId, userOpHash });
      } else {
        update(chainId, { state: 'failed', detail: 'the operation reverted on-chain', userOpHash: userOpHash as string });
        log(`${label}: reverted`, { chainId, userOpHash });
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      update(chainId, { state: 'failed', detail: message });
      log(`${label}: failed`, { chainId, error: message });
    }
  }

  const ok = !refusal && progress.every((row) => row.state === 'confirmed' || row.state === 'skipped') && appliedChainIds.length > 0;
  const outcome = { ok, refusal, progress, appliedChainIds };
  // D10: outcomes are written to the console as well as shown — an integrator debugging a
  // deployment is not dependent on a transient banner.
  log(`${label}: outcome`, {
    ok,
    appliedChainIds,
    perChain: progress.map(({ chainId, state, detail, userOpHash }) => ({ chainId, state, detail, userOpHash })),
  });
  return outcome;
}
