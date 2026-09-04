import type { ManagementController, ManagementFlow, ManagementState } from '@appliedblockchain/giano-wallet-kit';
import { ChainProgressList, ChainsNotice, FlowShell, RefusalNotice } from './shared';

/**
 * Renders the kit's `remove` flow (WM-27…WM-32). The index re-read per chain (WM-29) and
 * the last-owner guard (WM-28) are the kit's; this component only shows what is being
 * removed and how far each chain got.
 */
export function RemoveFlow({
  flow,
  state,
  actions,
}: {
  flow: Extract<ManagementFlow, { type: 'remove' }>;
  state: ManagementState;
  actions: ManagementController;
}) {
  if (flow.step === 'confirm') {
    const { owner } = flow;
    // WM-32: the confirmation identifies the credential by more than its name.
    const title = owner.name ?? (owner.kind === 'address' ? 'Ethereum account' : 'Passkey');
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
        {owner.createdAt ? (
          <div className="kv">
            <span className="k">Added</span>
            <span className="v">{new Date(owner.createdAt).toLocaleString()}</span>
          </div>
        ) : null}
        <div className="data-box" data-testid="manage-remove-identifier">
          {owner.kind === 'address' ? owner.address : owner.ownerBytes}
        </div>
        <p>Once removed it can no longer sign for this wallet. The passkey itself stays on its device — it will be refused, not deleted.</p>
        {flow.endsThisSession ? (
          <p data-testid="manage-remove-current-warning">
            <b>You are removing the credential this session is using.</b> When it completes you will be signed out on
            this device, and this passkey will no longer sign in anywhere (WM-30).
          </p>
        ) : null}
        <ChainsNotice chains={state.chains} />
        <div className="actions">
          <button onClick={flow.cancel}>Cancel</button>
          <button className="danger" onClick={flow.approve} data-testid="manage-remove-approve">
            Remove it
          </button>
        </div>
      </FlowShell>
    );
  }

  if (flow.step === 'applying') {
    return (
      <FlowShell title="Removing…">
        <p>Confirm each network's passkey prompt. Progress per network:</p>
        <ChainProgressList progress={flow.chains} />
      </FlowShell>
    );
  }

  if (flow.step === 'done') {
    return (
      <FlowShell title={flow.ok ? 'Credential removed' : flow.appliedChainIds.length > 0 ? 'Removed — attention needed' : 'Nothing was removed'}>
        {flow.refusal ? <RefusalNotice reason={flow.refusal.reason} message={flow.refusal.message} /> : null}
        <ChainProgressList progress={flow.chains} />
        {flow.endedSession ? (
          <p data-testid="manage-removed-signed-out">This session's credential was removed — you are now signed out.</p>
        ) : null}
        <div className="actions">
          {/* On endedSession the kit resolves the dismiss into the signed-out view (WM-30). */}
          <button className="primary" onClick={() => actions.dismissFlow()} data-testid="manage-flow-done">
            {flow.endedSession ? 'Sign out' : 'Back to the list'}
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
