import {
  encodeRemoveOwnerAtIndex,
  readOwnerSet,
  type OnChainOwner,
  type RegistryCredential,
} from '@appliedblockchain/giano-wallet-core';
import { useState } from 'react';
import { applyOwnerChange, type ChainProgress, type OwnerChangeOutcome } from './ops';
import { ChainProgressList, ChainsNotice, FlowShell, RefusalNotice, manageLog, type FlowProps } from './shared';

/**
 * Removing an owner (WM-27…WM-32). The index is re-read from each chain immediately
 * before the operation is constructed — a stale index is a failed transaction (WM-29) —
 * and the last-owner case never reaches this flow: the list refuses to offer it (WM-28)
 * and `removeLastOwner` has no encoder anywhere in the interface.
 */
export function RemoveFlow({
  api,
  runtimes,
  me,
  owner,
  credential,
  isCurrent,
  onDone,
  onSignedOut,
}: FlowProps & { owner: OnChainOwner; credential?: RegistryCredential; isCurrent: boolean; onSignedOut: () => void | Promise<void> }) {
  type Stage =
    | { step: 'consent' }
    | { step: 'running' }
    | { step: 'done'; outcome: OwnerChangeOutcome; endedSession: boolean }
    | { step: 'error'; message: string };

  const [stage, setStage] = useState<Stage>({ step: 'consent' });
  const [progress, setProgress] = useState<ChainProgress[]>([]);

  const approve = async () => {
    setStage({ step: 'running' });
    const outcome = await applyOwnerChange({
      runtimes,
      walletAddress: me.walletAddress,
      label: 'remove-owner',
      buildData: async (runtime) => {
        // WM-29: the index is read from THIS chain, now — never carried over from the
        // list render or from another chain, where indices can differ.
        const set = await readOwnerSet(runtime.publicClient, me.walletAddress);
        const found = set.owners.find((candidate) => candidate.ownerBytes.toLowerCase() === owner.ownerBytes.toLowerCase());
        if (!found) return null; // not an owner on this chain — nothing to remove here
        if (set.owners.length === 1) {
          // Defence in depth for WM-28: the UI never offers this, and the contract would
          // revert with LastOwner anyway — refuse legibly instead of submitting a revert.
          throw new Error('this is the last owner on this chain — removal refused');
        }
        return encodeRemoveOwnerAtIndex(found.index, found.ownerBytes);
      },
      onProgress: setProgress,
    });

    let endedSession = false;
    if (outcome.appliedChainIds.length > 0) {
      if (credential) {
        try {
          // The registry verifies on-chain before believing, then stops issuing sessions
          // for the credential (WM-31) — including this one, if it was removed (WM-30).
          const marked = await api.markCredentialRemoved(credential.credentialId);
          endedSession = marked.removedCurrentSession;
        } catch (error) {
          manageLog('remove-owner: registry mark failed — the chain change stands; the registry will show the divergence', (error as Error).message);
        }
      } else {
        await api
          .recordOwnerEvent({
            action: 'owner-removed',
            ownerKind: owner.kind,
            owner: owner.kind === 'address' ? (owner.address as string) : owner.ownerBytes,
            chainIds: outcome.appliedChainIds,
          })
          .catch((error) => manageLog('remove-owner: audit write failed', (error as Error).message));
      }
    }
    setStage({ step: 'done', outcome, endedSession });
  };

  if (stage.step === 'consent') {
    // WM-32: the confirmation identifies the credential by more than its name.
    const title = credential?.name ?? (owner.kind === 'address' ? 'Ethereum account' : 'Passkey');
    return (
      <FlowShell title="Review: remove this credential">
        <div className="kv">
          <span className="k">Credential</span>
          <span className="v">{title}</span>
        </div>
        <div className="kv">
          <span className="k">Kind</span>
          <span className="v">{owner.kind === 'address' ? 'Ethereum account' : 'passkey'}</span>
        </div>
        <div className="kv">
          <span className="k">Fingerprint</span>
          <span className="v" data-testid="manage-consent-fingerprint">{owner.fingerprint}</span>
        </div>
        {credential ? (
          <div className="kv">
            <span className="k">Added</span>
            <span className="v">{new Date(credential.createdAt).toLocaleString()}</span>
          </div>
        ) : null}
        <div className="data-box" data-testid="manage-remove-identifier">
          {owner.kind === 'address' ? owner.address : owner.ownerBytes}
        </div>
        <p>Once removed it can no longer sign for this wallet. The passkey itself stays on its device — it will be refused, not deleted.</p>
        {isCurrent ? (
          <p data-testid="manage-remove-current-warning">
            <b>You are removing the credential this session is using.</b> When it completes you will be signed out on
            this device, and this passkey will no longer sign in anywhere (WM-30).
          </p>
        ) : null}
        <ChainsNotice runtimes={runtimes} />
        <div className="actions">
          <button onClick={() => void onDone(false)}>Cancel</button>
          <button className="danger" onClick={() => void approve()} data-testid="manage-remove-approve">
            Remove it
          </button>
        </div>
      </FlowShell>
    );
  }

  if (stage.step === 'running') {
    return (
      <FlowShell title="Removing…">
        <p>Confirm each network's passkey prompt. Progress per network:</p>
        <ChainProgressList progress={progress} />
      </FlowShell>
    );
  }

  if (stage.step === 'done') {
    const { outcome, endedSession } = stage;
    return (
      <FlowShell title={outcome.ok ? 'Credential removed' : outcome.appliedChainIds.length > 0 ? 'Removed — attention needed' : 'Nothing was removed'}>
        {outcome.refusal ? <RefusalNotice refusal={outcome.refusal} /> : null}
        <ChainProgressList progress={outcome.progress} />
        {endedSession ? (
          <p data-testid="manage-removed-signed-out">This session's credential was removed — you are now signed out.</p>
        ) : null}
        <div className="actions">
          <button
            className="primary"
            onClick={() => void (endedSession ? onSignedOut() : onDone(true))}
            data-testid="manage-flow-done"
          >
            {endedSession ? 'Sign out' : 'Back to the list'}
          </button>
        </div>
      </FlowShell>
    );
  }

  return (
    <FlowShell title="Something went wrong">
      <div className="error" data-testid="manage-flow-error">{stage.message}</div>
      <div className="actions">
        <button onClick={() => void onDone(false)}>Back</button>
      </div>
    </FlowShell>
  );
}
