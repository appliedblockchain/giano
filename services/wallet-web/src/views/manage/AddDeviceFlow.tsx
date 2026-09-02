import { encodeAddOwnerPublicKey, ownerFingerprint, publicKeyOwnerBytes, type PendingAddition } from '@appliedblockchain/giano-wallet-core';
import { useEffect, useRef, useState } from 'react';
import type { SponsorshipPreflight } from '../../wallet';
import { applyOwnerChange, type ChainProgress, type OwnerChangeOutcome } from './ops';
import { ChainProgressList, ChainsNotice, FlowShell, RefusalNotice, manageLog, preflightManagement, type FlowProps } from './shared';

/**
 * The cross-device addition (WM-18…WM-23, D8). This device — the AUTHORISING one — opens
 * the pending addition, displays the claim code, polls for the deposited key, and asks
 * the user to compare fingerprints before anything is signed (WM-20, WM-21). The
 * fingerprint is recomputed here from the key AS RECEIVED: it is the mechanism by which
 * the user, rather than the backend, chooses what gets added.
 */
export function AddDeviceFlow({ api, runtimes, config, me, onDone }: FlowProps) {
  type Stage =
    | { step: 'preflight' }
    | { step: 'refused'; refusal: Extract<SponsorshipPreflight, { state: 'refused' }> }
    | { step: 'code'; slotId: string; claimCode: string; expiresAt: string }
    | { step: 'consent'; slotId: string; publicKey: { x: `0x${string}`; y: `0x${string}` }; fingerprint: string }
    | { step: 'running' }
    | { step: 'declined' }
    | { step: 'expired' }
    | { step: 'done'; outcome: OwnerChangeOutcome; slotId: string }
    | { step: 'error'; message: string };

  const [stage, setStage] = useState<Stage>({ step: 'preflight' });
  const [name, setName] = useState(`Another device · ${new Date().toLocaleDateString()}`);
  const [progress, setProgress] = useState<ChainProgress[]>([]);
  const started = useRef(false);

  const runtime = runtimes.runtimeFor(runtimes.servedChainIds[0]);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    void (async () => {
      try {
        const preflight = await preflightManagement(runtime, me.walletAddress);
        if (preflight.state === 'refused') {
          manageLog('add-device: sponsorship refused before consent', preflight);
          setStage({ step: 'refused', refusal: preflight });
          return;
        }
        const slot = await api.openPendingAddition();
        manageLog('add-device: pending addition opened', { slotId: slot.id, expiresAt: slot.expiresAt });
        setStage({ step: 'code', slotId: slot.id, claimCode: slot.claimCode, expiresAt: slot.expiresAt });
      } catch (error) {
        setStage({ step: 'error', message: (error as Error).message });
      }
    })();
  }, [api, me, runtime]);

  // Poll the slot while the code is on screen (D8 phase 5): both devices are present and
  // awake at the same time by design.
  useEffect(() => {
    if (stage.step !== 'code') return;
    const timer = setInterval(() => {
      void (async () => {
        try {
          const slot: PendingAddition = await api.getPendingAddition(stage.slotId);
          if (slot.status === 'filled' && slot.publicKey) {
            // Recomputed from x,y AS RECEIVED — never trusted from the backend's own claim.
            const fingerprint = ownerFingerprint(publicKeyOwnerBytes(slot.publicKey.x, slot.publicKey.y));
            manageLog('add-device: key deposited', { fingerprint });
            setStage({ step: 'consent', slotId: stage.slotId, publicKey: slot.publicKey, fingerprint });
          } else if (slot.status === 'expired') {
            setStage({ step: 'expired' });
          }
        } catch (error) {
          const code = (error as { code?: string }).code;
          if (code === 'pending-expired') setStage({ step: 'expired' });
        }
      })();
    }, 2000);
    return () => clearInterval(timer);
  }, [api, stage]);

  const decline = async (slotId: string) => {
    // WM-21/WM-52: a mismatch is declined, counted, and nothing is added.
    await api.declinePendingAddition(slotId).catch(() => undefined);
    manageLog('add-device: fingerprint declined — nothing added');
    setStage({ step: 'declined' });
  };

  const approve = async (slotId: string, publicKey: { x: `0x${string}`; y: `0x${string}` }) => {
    setStage({ step: 'running' });
    const outcome = await applyOwnerChange({
      runtimes,
      walletAddress: me.walletAddress,
      label: 'add-device',
      buildData: async () => encodeAddOwnerPublicKey(publicKey.x, publicKey.y),
      onProgress: setProgress,
    });
    if (outcome.appliedChainIds.length > 0) {
      try {
        await api.completePendingAddition(slotId, { chainIds: outcome.appliedChainIds, name: name.trim() || undefined });
      } catch (error) {
        manageLog('add-device: binding failed after on-chain success (WM-04 will show it honestly)', (error as Error).message);
      }
    }
    setStage({ step: 'done', outcome, slotId });
  };

  if (stage.step === 'preflight') {
    return (
      <FlowShell title="Add a passkey on another device">
        <p>
          <span className="spinner" /> Checking that this change is covered…
        </p>
      </FlowShell>
    );
  }

  if (stage.step === 'refused') {
    return (
      <>
        <RefusalNotice refusal={stage.refusal} />
        <div className="actions">
          <button onClick={() => void onDone(false)}>Back</button>
        </div>
      </>
    );
  }

  if (stage.step === 'code') {
    const formatted = `${stage.claimCode.slice(0, 4)}-${stage.claimCode.slice(4)}`;
    return (
      <FlowShell title="On your other device…">
        <p>
          1. Open <b>{window.location.origin}</b> on the other device and choose <b>“Add this device to an existing wallet”</b>.
        </p>
        <p>2. Enter this code there:</p>
        <div className="data-box" style={{ fontSize: 26, textAlign: 'center', letterSpacing: 3 }} data-testid="manage-claim-code">
          {formatted}
        </div>
        <p>
          The code only routes the other device here — it cannot add anything by itself. It expires at{' '}
          {new Date(stage.expiresAt).toLocaleTimeString()}.
        </p>
        <p>
          <span className="spinner" /> Waiting for the other device…
        </p>
        <div className="actions">
          <button onClick={() => void decline(stage.slotId)}>Cancel</button>
        </div>
      </FlowShell>
    );
  }

  if (stage.step === 'consent') {
    // WM-20/WM-21: the consent screen shows the fingerprint of the key it is about to
    // sign for, and asks the user to compare it with the other device's screen.
    return (
      <FlowShell title="Compare the fingerprints">
        <p>
          Your other device is showing a fingerprint for the passkey it just created. Approve <b>only if it matches</b>{' '}
          this one — the match is what stops anyone in the middle substituting their own key.
        </p>
        <div className="data-box" style={{ fontSize: 26, textAlign: 'center', letterSpacing: 3 }} data-testid="manage-consent-fingerprint">
          {stage.fingerprint}
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
          <button className="danger" onClick={() => void decline(stage.slotId)} data-testid="manage-fingerprint-decline">
            They don't match
          </button>
          <button className="primary" onClick={() => void approve(stage.slotId, stage.publicKey)} data-testid="manage-fingerprint-approve">
            They match — add it
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

  if (stage.step === 'declined') {
    return (
      <FlowShell title="Nothing was added">
        <p data-testid="manage-declined-note">
          The pending addition was declined and cannot be used. If the fingerprints did not match, the key offered to
          you was not the one your other device created — nothing was signed, and the attempt has been recorded.
        </p>
        <div className="actions">
          <button className="primary" onClick={() => void onDone(false)} data-testid="manage-flow-done">
            Back to the list
          </button>
        </div>
      </FlowShell>
    );
  }

  if (stage.step === 'expired') {
    // WM-23: distinguishable from a network failure, with the action the user can take.
    return (
      <FlowShell title="The code expired">
        <p data-testid="manage-expired-note">
          Pending additions expire after a few minutes and cannot be resumed. Start again — the other device will need
          to create a fresh passkey.
        </p>
        <div className="actions">
          <button className="primary" onClick={() => void onDone(false)} data-testid="manage-flow-done">
            Back to the list
          </button>
        </div>
      </FlowShell>
    );
  }

  if (stage.step === 'done') {
    const { outcome } = stage;
    return (
      <FlowShell title={outcome.ok ? 'Passkey added' : outcome.appliedChainIds.length > 0 ? 'Passkey added — attention needed' : 'Nothing was added'}>
        {outcome.refusal ? <RefusalNotice refusal={outcome.refusal} /> : null}
        <ChainProgressList progress={outcome.progress} />
        <p>The other device can now sign in with its new passkey.</p>
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
