import type { ChainProgress, ManagementChainStatus, SponsorshipRefusalReason } from '@appliedblockchain/giano-wallet-kit';
import type { ReactNode } from 'react';
import { refusalCopy } from '../sponsorship-copy';

/** The WM-48/WM-49 copy: who can act on the refusal, keyed off the machine-readable reason. */
export function RefusalNotice({ reason, message }: { reason: SponsorshipRefusalReason; message: string }) {
  const copy = refusalCopy(reason);
  return (
    <div className="card" data-testid="manage-sponsorship-refusal" data-reason={reason}>
      <h2>{copy.title}</h2>
      <p>{copy.body}</p>
      <p>
        <b>{copy.action}</b>
      </p>
      <p style={{ fontSize: 12 }}>{message}</p>
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
export function ChainsNotice({ chains }: { chains: ManagementChainStatus[] }) {
  const names = chains.map((chain) => `${chain.chainName} (${chain.chainId})`);
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

export const inputStyle = {
  width: '100%',
  marginTop: 4,
  borderRadius: 8,
  border: '1px solid var(--border)',
  padding: '8px',
  background: 'var(--bg)',
  color: 'var(--fg)',
} as const;
