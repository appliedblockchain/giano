import type { ManagementController, ManagementFlow, ManagementState } from '@appliedblockchain/giano-wallet-kit';
import { useEffect, useRef } from 'react';
import { ChainProgressList, ChainsNotice, FlowShell, inputStyle, RefusalNotice } from './shared';

export type AddVariant = 'this-device' | 'second-device';

/**
 * Renders the kit's `add` flow (WM-14, WM-18…WM-23). Every step — the claim code, the
 * fingerprint to compare, the per-chain progress — comes from the controller; this
 * component only draws it. Which entry point started the flow ('this device' vs 'another
 * device') is a copy decision, so it lives here, not in the kit.
 */
export function AddFlow({
  flow,
  state,
  actions,
  variant,
}: {
  flow: Extract<ManagementFlow, { type: 'add' }>;
  state: ManagementState;
  actions: ManagementController;
  variant: AddVariant;
}) {
  const titles = variant === 'this-device' ? 'Add a passkey on this device' : 'Add a passkey on another device';

  // Seed the default credential name once per confirm step — the copy is the wallet's, not
  // the kit's, so the default lives here.
  const seeded = useRef(false);
  useEffect(() => {
    if (flow.step === 'confirm-fingerprint' && !seeded.current) {
      seeded.current = true;
      flow.setName(variant === 'this-device' ? `Backup passkey · ${new Date().toLocaleDateString()}` : `Another device · ${new Date().toLocaleDateString()}`);
    }
  }, [flow, variant]);

  if (flow.step === 'preparing') {
    return (
      <FlowShell title={titles}>
        <p>
          <span className="spinner" /> Checking that this change is covered…
        </p>
        <div className="actions">
          <button onClick={() => actions.dismissFlow()}>Cancel</button>
        </div>
      </FlowShell>
    );
  }

  if (flow.step === 'claim-code') {
    const formatted = `${flow.claimCode.slice(0, 4)}-${flow.claimCode.slice(4)}`;
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
          {new Date(flow.expiresAt).toLocaleTimeString()}.
        </p>
        <p>
          <span className="spinner" /> Waiting for the other device…
        </p>
        <div className="actions">
          <button onClick={flow.cancel}>Cancel</button>
        </div>
      </FlowShell>
    );
  }

  if (flow.step === 'confirm-fingerprint') {
    // WM-17/WM-20/WM-21: the consent screen shows the fingerprint of the key it is about
    // to sign for — recomputed by the kit from the key as received — BEFORE the
    // authorising signature's passkey prompt is raised.
    const nameInput = (
      <label style={{ fontSize: 13 }}>
        Name it (you can rename later)
        <input value={flow.name} onChange={(event) => flow.setName(event.target.value)} style={inputStyle} data-testid="manage-add-name" />
      </label>
    );

    if (variant === 'this-device') {
      return (
        <FlowShell title="Review: add this passkey">
          <p>A new passkey was created on this device. Approving adds it as an owner of your wallet, with full and equal control.</p>
          <div className="kv">
            <span className="k">Fingerprint</span>
            <span className="v" data-testid="manage-consent-fingerprint">{flow.fingerprint}</span>
          </div>
          <ChainsNotice chains={state.chains} />
          {nameInput}
          <div className="actions">
            <button className="danger" onClick={flow.decline}>
              Cancel
            </button>
            <button className="primary" onClick={flow.approve} data-testid="manage-add-approve">
              Add passkey
            </button>
          </div>
        </FlowShell>
      );
    }

    return (
      <FlowShell title="Compare the fingerprints">
        <p>
          Your other device is showing a fingerprint for the passkey it just created. Approve <b>only if it matches</b>{' '}
          this one — the match is what stops anyone in the middle substituting their own key.
        </p>
        <div className="data-box" style={{ fontSize: 26, textAlign: 'center', letterSpacing: 3 }} data-testid="manage-consent-fingerprint">
          {flow.fingerprint}
        </div>
        <ChainsNotice chains={state.chains} />
        {nameInput}
        <div className="actions">
          <button className="danger" onClick={flow.decline} data-testid="manage-fingerprint-decline">
            They don't match
          </button>
          <button className="primary" onClick={flow.approve} data-testid="manage-fingerprint-approve">
            They match — add it
          </button>
        </div>
      </FlowShell>
    );
  }

  if (flow.step === 'applying') {
    return (
      <FlowShell title="Adding the passkey…">
        <p>Confirm each network's passkey prompt. Progress per network:</p>
        <ChainProgressList progress={flow.chains} />
      </FlowShell>
    );
  }

  if (flow.step === 'declined') {
    return (
      <FlowShell title="Nothing was added">
        <p data-testid="manage-declined-note">
          The pending addition was declined and cannot be used. If the fingerprints did not match, the key offered to
          you was not the one your other device created — nothing was signed, and the attempt has been recorded.
        </p>
        <div className="actions">
          <button className="primary" onClick={() => actions.dismissFlow()} data-testid="manage-flow-done">
            Back to the list
          </button>
        </div>
      </FlowShell>
    );
  }

  if (flow.step === 'expired') {
    // WM-23: distinguishable from a network failure, with the action the user can take.
    return (
      <FlowShell title="The code expired">
        <p data-testid="manage-expired-note">
          Pending additions expire after a few minutes and cannot be resumed. Start again — the other device will need
          to create a fresh passkey.
        </p>
        <div className="actions">
          <button className="primary" onClick={() => actions.dismissFlow()} data-testid="manage-flow-done">
            Back to the list
          </button>
        </div>
      </FlowShell>
    );
  }

  if (flow.step === 'done') {
    return (
      <FlowShell title={flow.ok ? 'Passkey added' : flow.appliedChainIds.length > 0 ? 'Passkey added — attention needed' : 'Nothing was added'}>
        {flow.refusal ? <RefusalNotice reason={flow.refusal.reason} message={flow.refusal.message} /> : null}
        <ChainProgressList progress={flow.chains} />
        {!flow.ok && flow.appliedChainIds.length > 0 ? (
          <p>The change is not complete on every network (WM-44) — the owner list will show the difference until it is reconciled.</p>
        ) : null}
        {variant === 'second-device' && flow.ok ? <p>The other device can now sign in with its new passkey.</p> : null}
        <div className="actions">
          <button className="primary" onClick={() => actions.dismissFlow()} data-testid="manage-flow-done">
            Back to the list
          </button>
        </div>
      </FlowShell>
    );
  }

  // flow.step === 'error'
  return (
    <FlowShell title="Something went wrong">
      <div className="error" data-testid="manage-flow-error">{flow.message}</div>
      <div className="actions">
        <button onClick={() => actions.dismissFlow()}>Back</button>
      </div>
    </FlowShell>
  );
}
