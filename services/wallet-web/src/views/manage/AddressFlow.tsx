import type { AddressInputError, ManagementController, ManagementFlow, ManagementState } from '@appliedblockchain/giano-wallet-kit';
import { ChainProgressList, ChainsNotice, FlowShell, RefusalNotice } from './shared';

/**
 * Renders the kit's `address` flow — adding an externally-owned account as an owner
 * (WM-24…WM-26, BR-15). Validation, checksum rules and the acknowledgement gate are the
 * kit's; the wording is this wallet's.
 */

const INPUT_ERROR_COPY: Record<AddressInputError, string> = {
  'invalid-address': 'Not a valid Ethereum address (check the EIP-55 checksum).',
  'not-checksummed': 'Enter the address in its checksummed (mixed-case) form, exactly as your wallet shows it.',
  'own-wallet': 'That is this wallet’s own address.',
};

export function AddressFlow({
  flow,
  state,
  actions,
}: {
  flow: Extract<ManagementFlow, { type: 'address' }>;
  state: ManagementState;
  actions: ManagementController;
}) {
  if (flow.step === 'preparing') {
    return (
      <FlowShell title="Add an Ethereum account">
        <p>
          <span className="spinner" /> Checking that this change is covered…
        </p>
      </FlowShell>
    );
  }

  if (flow.step === 'input') {
    return (
      <FlowShell title="Add an Ethereum account">
        <p>A software or hardware wallet you already hold can act on this wallet as an owner.</p>
        <input
          value={flow.value}
          onChange={(event) => flow.setAddress(event.target.value)}
          placeholder="0x… (checksummed address)"
          style={{ width: '100%', borderRadius: 8, border: '1px solid var(--border)', padding: '10px', background: 'var(--bg)', color: 'var(--fg)', fontFamily: 'ui-monospace, monospace' }}
          data-testid="manage-address-input"
        />
        {flow.error ? <div className="error" data-testid="manage-address-error">{INPUT_ERROR_COPY[flow.error]}</div> : null}
        <div className="actions">
          <button onClick={() => actions.dismissFlow()}>Cancel</button>
          <button className="primary" onClick={flow.continue} disabled={!flow.value.trim()} data-testid="manage-address-continue">
            Continue
          </button>
        </div>
      </FlowShell>
    );
  }

  if (flow.step === 'confirm') {
    return (
      <FlowShell title="Review: add this account">
        {/* WM-25: full and unabbreviated. */}
        <div className="data-box" style={{ fontSize: 14, textAlign: 'center' }} data-testid="manage-address-full">
          {flow.address}
        </div>
        {/* WM-26: what is granted, plainly. */}
        <p data-testid="manage-address-grant-note">
          This account gains <b>full and equal control</b> of your wallet — no threshold, no limit. It can also act{' '}
          <b>directly on-chain</b>, outside the app's relay: those transactions are not covered by the relay's policy
          checks or its audit trail, and it pays its own gas for them.
        </p>
        <label style={{ display: 'flex', gap: 8, fontSize: 13, alignItems: 'flex-start' }}>
          <input type="checkbox" checked={flow.acknowledged} onChange={(event) => flow.acknowledge(event.target.checked)} data-testid="manage-address-understood" />
          <span>I checked the address character by character and I understand what it is being granted.</span>
        </label>
        <ChainsNotice chains={state.chains} />
        <div className="actions">
          <button onClick={flow.back}>Back</button>
          <button className="primary" onClick={flow.approve} disabled={!flow.acknowledged} data-testid="manage-address-approve">
            Add account
          </button>
        </div>
      </FlowShell>
    );
  }

  if (flow.step === 'applying') {
    return (
      <FlowShell title="Adding the account…">
        <p>Confirm each network's passkey prompt. Progress per network:</p>
        <ChainProgressList progress={flow.chains} />
      </FlowShell>
    );
  }

  if (flow.step === 'done') {
    return (
      <FlowShell title={flow.ok ? 'Account added' : flow.appliedChainIds.length > 0 ? 'Account added — attention needed' : 'Nothing was added'}>
        {flow.refusal ? <RefusalNotice reason={flow.refusal.reason} message={flow.refusal.message} /> : null}
        <ChainProgressList progress={flow.chains} />
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
