import type { ManagementController, ManagementFlow } from '@appliedblockchain/giano-wallet-kit';
import { FlowShell } from './shared';

/**
 * Renders the kit's `claim` flow — the NEW device's half of a cross-device addition (D8
 * phase 4): enter the claim code shown on the authorising device, create a passkey,
 * deposit it — then display the fingerprint for the user to compare over on the other
 * screen (WM-20). Nothing here needs or receives a session: the code routes, it does not
 * authorise (WM-19).
 */
export function ClaimFlow({ flow, actions }: { flow: Extract<ManagementFlow, { type: 'claim' }>; actions: ManagementController }) {
  if (flow.step === 'input' || flow.step === 'depositing') {
    const depositing = flow.step === 'depositing';
    return (
      <FlowShell title="Add this device to an existing wallet">
        <p>Enter the code shown on the device that already holds a passkey for the wallet. Both devices need to stay open.</p>
        <input
          value={flow.step === 'input' ? flow.code : ''}
          onChange={(event) => flow.step === 'input' && flow.setCode(event.target.value)}
          placeholder="e.g. AB3D-9KFM"
          autoCapitalize="characters"
          disabled={depositing}
          style={{ width: '100%', borderRadius: 8, border: '1px solid var(--border)', padding: '10px', background: 'var(--bg)', color: 'var(--fg)', fontFamily: 'ui-monospace, monospace', fontSize: 18, textAlign: 'center', letterSpacing: 2 }}
          data-testid="manage-claim-input"
        />
        <div className="actions">
          <button onClick={() => actions.dismissFlow()}>Back</button>
          <button
            className="primary"
            onClick={() => flow.step === 'input' && flow.submit()}
            disabled={depositing || (flow.step === 'input' && flow.code.trim().length < 4)}
            data-testid="manage-claim-continue"
          >
            {depositing ? 'Creating passkey…' : 'Create a passkey here'}
          </button>
        </div>
      </FlowShell>
    );
  }

  if (flow.step === 'deposited') {
    return (
      <FlowShell title="Now compare the fingerprints">
        <p>
          This device created a passkey with the fingerprint below. Your other device will show the fingerprint of the
          key it is being asked to add — approve there <b>only if the two match</b>.
        </p>
        <div className="data-box" style={{ fontSize: 26, textAlign: 'center', letterSpacing: 3 }} data-testid="manage-claim-fingerprint">
          {flow.fingerprint}
        </div>
        <p data-testid="manage-claim-next">
          Once it is approved and confirmed on-chain, come back here and choose <b>“Use a passkey created on another
          device”</b> to sign in with it.
        </p>
        <div className="actions">
          <button className="primary" onClick={() => actions.dismissFlow()} data-testid="manage-flow-done">
            Done
          </button>
        </div>
      </FlowShell>
    );
  }

  // WM-23: an expired, unknown or already-used code is refused with a reason the user can
  // act on — visibly different from a network failure. The code is the kit's; the copy is ours.
  const explanation =
    flow.code === 'pending-expired'
      ? 'The code expired. Ask your other device for a fresh one and try again — a new passkey will be created.'
      : flow.code === 'pending-unknown'
        ? 'No pending addition matches this code. Check it character by character on the other device.'
        : flow.code === 'pending-consumed' || flow.code === 'pending-already-filled'
          ? 'This code was already used. Ask your other device for a fresh one.'
          : 'Something went wrong talking to the wallet service — this may be a connection problem; try again.';

  return (
    <FlowShell title="That didn't work">
      <div className="error" data-testid="manage-claim-error" data-code={flow.code}>
        {explanation}
      </div>
      <p style={{ fontSize: 12 }}>{flow.message}</p>
      <div className="actions">
        <button onClick={() => actions.dismissFlow()}>Back</button>
        <button className="primary" onClick={flow.retry}>
          Try again
        </button>
      </div>
    </FlowShell>
  );
}
