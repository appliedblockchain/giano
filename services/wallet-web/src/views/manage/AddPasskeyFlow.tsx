import {
  ChainType,
  depositPasskeyIntoPendingAddition,
  encodeAddOwnerPublicKey,
  type DepositedPasskey,
} from '@appliedblockchain/giano-wallet-core';
import { useEffect, useRef, useState } from 'react';
import type { SponsorshipPreflight } from '../../wallet';
import { applyOwnerChange, type ChainProgress, type OwnerChangeOutcome } from './ops';
import { ChainProgressList, ChainsNotice, FlowShell, RefusalNotice, manageLog, preflightManagement, type FlowProps } from './shared';

/**
 * Adding a passkey created in the CURRENT session (WM-14): the same pending-addition
 * machinery as the cross-device flow with the handoff collapsed — this device opens the
 * slot, creates the credential and deposits it itself, so a hardware security key present
 * on the device becomes a backup credential in one sitting.
 */
export function AddPasskeyFlow({ api, runtimes, config, me, onDone }: FlowProps) {
  type Stage =
    | { step: 'preflight' }
    | { step: 'refused'; refusal: Extract<SponsorshipPreflight, { state: 'refused' }> }
    | { step: 'creating' }
    | { step: 'consent'; slotId: string; deposited: DepositedPasskey }
    | { step: 'running'; slotId: string; deposited: DepositedPasskey }
    | { step: 'done'; outcome: OwnerChangeOutcome }
    | { step: 'error'; message: string };

  const [stage, setStage] = useState<Stage>({ step: 'preflight' });
  const [name, setName] = useState(`Backup passkey · ${new Date().toLocaleDateString()}`);
  const [progress, setProgress] = useState<ChainProgress[]>([]);
  const started = useRef(false);

  const runtime = runtimes.runtimeFor(runtimes.servedChainIds[0]);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    void (async () => {
      try {
        // Refusal BEFORE any passkey ceremony (WM-68).
        const preflight = await preflightManagement(runtime, me.walletAddress);
        if (preflight.state === 'refused') {
          manageLog('add-passkey: sponsorship refused before consent', preflight);
          setStage({ step: 'refused', refusal: preflight });
          return;
        }
        setStage({ step: 'creating' });
        const slot = await api.openPendingAddition();
        const userId = await runtime.injection.encodeUserId(
          crypto.randomUUID().replace(/-/g, ''),
          runtime.factoryAddress,
          ChainType.EVM,
        );
        const deposited = await depositPasskeyIntoPendingAddition({
          api,
          claimCode: slot.claimCode,
          userId,
          userName: config.branding.name,
        });
        manageLog('add-passkey: credential created and deposited', { fingerprint: deposited.fingerprint });
        setStage({ step: 'consent', slotId: slot.id, deposited });
      } catch (error) {
        const message = (error as Error).message;
        manageLog('add-passkey: failed', message);
        setStage({ step: 'error', message });
      }
    })();
  }, [api, config, me, runtime]);

  const approve = async (slotId: string, deposited: DepositedPasskey) => {
    setStage({ step: 'running', slotId, deposited });
    const outcome = await applyOwnerChange({
      runtimes,
      walletAddress: me.walletAddress,
      label: 'add-passkey',
      buildData: async () => encodeAddOwnerPublicKey(deposited.publicKey.x, deposited.publicKey.y),
      onProgress: setProgress,
    });
    if (outcome.appliedChainIds.length > 0) {
      // The chain confirmed FIRST; only now does the registry bind (WM-15).
      try {
        await api.completePendingAddition(slotId, { chainIds: outcome.appliedChainIds, name: name.trim() || undefined });
      } catch (error) {
        manageLog('add-passkey: binding failed after on-chain success — the owner will show as added outside this deployment (WM-04)', (error as Error).message);
      }
    }
    setStage({ step: 'done', outcome });
  };

  const cancel = async (slotId?: string) => {
    if (slotId) await api.declinePendingAddition(slotId).catch(() => undefined);
    await onDone(false);
  };

  if (stage.step === 'preflight' || stage.step === 'creating') {
    return (
      <FlowShell title="Add a passkey on this device">
        <p>
          <span className="spinner" />
          {stage.step === 'preflight' ? 'Checking that this change is covered…' : 'Follow the passkey prompt to create the new credential…'}
        </p>
        <div className="actions">
          <button onClick={() => void cancel()}>Cancel</button>
        </div>
      </FlowShell>
    );
  }

  if (stage.step === 'refused') {
    return (
      <>
        <RefusalNotice refusal={stage.refusal} />
        <div className="actions">
          <button onClick={() => void cancel()}>Back</button>
        </div>
      </>
    );
  }

  if (stage.step === 'consent') {
    // WM-17: what is being added — by the WM-03 identifier — BEFORE the authorising
    // signature's passkey prompt is raised.
    return (
      <FlowShell title="Review: add this passkey">
        <p>A new passkey was created on this device. Approving adds it as an owner of your wallet, with full and equal control.</p>
        <div className="kv">
          <span className="k">Fingerprint</span>
          <span className="v" data-testid="manage-consent-fingerprint">{stage.deposited.fingerprint}</span>
        </div>
        <ChainsNotice runtimes={runtimes} />
        <label style={{ fontSize: 13 }}>
          Name it (you can rename later)
          <input
            value={name}
            onChange={(event) => setName(event.target.value)}
            style={{ width: '100%', marginTop: 4, borderRadius: 8, border: '1px solid var(--border)', padding: '8px', background: 'var(--bg)', color: 'var(--fg)' }}
            data-testid="manage-add-name"
          />
        </label>
        <div className="actions">
          <button className="danger" onClick={() => void cancel(stage.slotId)}>
            Cancel
          </button>
          <button className="primary" onClick={() => void approve(stage.slotId, stage.deposited)} data-testid="manage-add-approve">
            Add passkey
          </button>
        </div>
      </FlowShell>
    );
  }

  if (stage.step === 'running') {
    return (
      <FlowShell title="Adding the passkey…">
        <p>Confirm each network's passkey prompt. Progress per network:</p>
        <ChainProgressList progress={progress} />
      </FlowShell>
    );
  }

  if (stage.step === 'done') {
    const { outcome } = stage;
    return (
      <FlowShell title={outcome.ok ? 'Passkey added' : outcome.appliedChainIds.length > 0 ? 'Passkey added — attention needed' : 'Nothing was added'}>
        {outcome.refusal ? <RefusalNotice refusal={outcome.refusal} /> : null}
        <ChainProgressList progress={outcome.progress} />
        {!outcome.ok && outcome.appliedChainIds.length > 0 ? (
          <p>The change is not complete on every network (WM-44) — the owner list will show the difference until it is reconciled.</p>
        ) : null}
        <div className="actions">
          <button className="primary" onClick={() => void onDone(true)} data-testid="manage-flow-done">
            Back to the list
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
