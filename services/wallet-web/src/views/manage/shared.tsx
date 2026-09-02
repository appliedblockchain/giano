import { encodeAddOwnerPublicKey } from '@appliedblockchain/giano-wallet-core';
import type { ReactNode } from 'react';
import { pad } from 'viem';
import type { WalletConfig } from '../../config';
import type { SponsorshipPreflight, WalletRuntime, WalletRuntimes } from '../../wallet';
import { refusalCopy } from '../sponsorship-copy';
import type { ChainProgress } from './ops';
import type { Me } from '../Manage';
import type { WalletManagementApi } from '@appliedblockchain/giano-wallet-core';

/** What every management flow receives. */
export type FlowProps = {
  api: WalletManagementApi;
  runtimes: WalletRuntimes;
  config: WalletConfig;
  me: Me;
  onDone: (refresh: boolean) => void | Promise<void>;
};

export const manageLog = (label: string, data?: unknown) => console.log(`[giano-wallet:manage] ${label}`, data ?? '');

/**
 * Asks the rules engine whether a wallet-management operation would be sponsored, BEFORE
 * any ceremony is started (WM-68): a user must never be walked through a passkey prompt
 * for an operation that was already refused. The calldata is a representative
 * addOwnerPublicKey self-call — the rule is structural (a call from the wallet to
 * itself), so any management operation answers the same.
 */
export async function preflightManagement(runtime: WalletRuntime, walletAddress: `0x${string}`): Promise<SponsorshipPreflight> {
  if (!runtime.provider.getSmartAccount()) {
    await runtime.provider.request({ method: 'giano_restoreAccount', params: [] }).catch(() => undefined);
  }
  if (!runtime.provider.getSmartAccount()) {
    return { state: 'unavailable', message: 'the wallet is not connected yet' };
  }
  const zero = pad('0x00', { size: 32 });
  return runtime.checkSponsorship({ to: walletAddress, data: encodeAddOwnerPublicKey(zero, zero) });
}

/** The WM-48/WM-49 copy: who can act on the refusal, keyed off the machine-readable reason. */
export function RefusalNotice({ refusal }: { refusal: Extract<SponsorshipPreflight, { state: 'refused' }> }) {
  const copy = refusalCopy(refusal.reason);
  return (
    <div className="card" data-testid="manage-sponsorship-refusal" data-reason={refusal.reason}>
      <h2>{copy.title}</h2>
      <p>{copy.body}</p>
      <p>
        <b>{copy.action}</b>
      </p>
      <p style={{ fontSize: 12 }}>{refusal.message}</p>
    </div>
  );
}

/** Per-chain progress (WM-44): visible until every served chain has answered. */
export function ChainProgressList({ progress }: { progress: ChainProgress[] }) {
  const describe = (row: ChainProgress) => {
    switch (row.state) {
      case 'waiting':
        return 'waiting…';
      case 'checking':
        return 'checking…';
      case 'skipped':
        return row.detail ?? 'skipped';
      case 'refused':
        return row.detail ?? 'refused';
      case 'submitted':
        return 'submitted — waiting for confirmation…';
      case 'confirmed':
        return 'confirmed ✓';
      case 'failed':
        return `failed: ${row.detail ?? 'unknown error'}`;
    }
  };
  return (
    <div data-testid="manage-chain-progress">
      {progress.map((row) => (
        <div className="kv" key={row.chainId} data-testid={`manage-chain-progress-${row.chainId}`} data-state={row.state}>
          <span className="k">
            {row.chainName} ({row.chainId})
          </span>
          <span className="v">{describe(row)}</span>
        </div>
      ))}
    </div>
  );
}

/** Names every served chain the change will be attempted on (WM-43). */
export function ChainsNotice({ runtimes }: { runtimes: WalletRuntimes }) {
  const names = runtimes.servedChainIds.map((chainId) => `${runtimes.descriptorFor(chainId).name} (${chainId})`);
  return (
    <p data-testid="manage-chains-notice">
      This change applies on every network this wallet serves: <b>{names.join(', ')}</b>. A network where the wallet is
      not deployed yet is skipped and stated.
    </p>
  );
}

export function FlowShell({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="card">
      <h2>{title}</h2>
      {children}
    </div>
  );
}
