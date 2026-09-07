import type { ManagementController, OwnerRow } from '@appliedblockchain/giano-wallet-kit';
import { useManagement } from '@appliedblockchain/giano-wallet-kit/react';
import { useEffect, useState } from 'react';
import { AddFlow, type AddVariant } from './manage/AddFlow';
import { AddressFlow } from './manage/AddressFlow';
import { ClaimFlow } from './manage/ClaimFlow';
import { RemoveFlow } from './manage/RemoveFlow';
import { RefusalNotice } from './manage/shared';

/**
 * The wallet-management interface (WM-01…WM-11), rendered over the kit's headless
 * controller (WK-16, WK-30): the owner set read from the chain, reconciled against the
 * registry — with divergence shown rather than hidden — plus the add and remove flows.
 * Everything ordering-critical (chain-before-registry, index re-reads, fingerprint
 * recompute, the last-owner guard) is the kit's; this file is pixels.
 *
 * Reached two ways with the same capabilities (WM-56): standalone on the wallet origin,
 * and from an application through `giano_openWalletManagement` (then `onClose` resolves
 * the transport request with nothing, WM-40).
 */
export function Manage({ onClose }: { onClose?: () => void }) {
  const { state, flow, actions } = useManagement();
  // Which entry point started the add flow is a copy decision, so it lives in the view.
  const [addVariant, setAddVariant] = useState<AddVariant>('this-device');

  // ── Active flow ──────────────────────────────────────────────────────────────────
  if (flow) {
    if (flow.type === 'add') return <AddFlow flow={flow} state={state} actions={actions} variant={addVariant} />;
    if (flow.type === 'address') return <AddressFlow flow={flow} state={state} actions={actions} />;
    if (flow.type === 'remove') return <RemoveFlow flow={flow} state={state} actions={actions} />;
    if (flow.type === 'claim') return <ClaimFlow flow={flow} actions={actions} />;
    // flow.type === 'refused': a sponsorship refusal met before any passkey prompt (WM-68)
    return (
      <>
        <RefusalNotice reason={flow.reason} message={flow.message} />
        <div className="actions">
          <button onClick={flow.back}>Back</button>
        </div>
      </>
    );
  }

  // ── Signed out (WM-57): offer sign-in rather than failing ────────────────────────
  if (state.view === 'signed-out') {
    return (
      <>
        <div className="card">
          <h2>Manage your wallet</h2>
          <p>Sign in to see and control the passkeys and accounts that can act on your wallet.</p>
          {state.error ? <div className="error" data-testid="manage-error">{state.error}</div> : null}
        </div>
        <div className="actions" style={{ flexDirection: 'column' }}>
          <button className="primary" onClick={() => void actions.signIn()} disabled={state.busy} data-testid="manage-sign-in">
            {state.busy ? 'Waiting for passkey…' : 'Sign in with passkey'}
          </button>
          <button onClick={() => void actions.signInWithExistingPasskey()} disabled={state.busy} data-testid="manage-sign-in-existing">
            Use a passkey created on another device
          </button>
          <button onClick={() => actions.startClaimOnThisDevice()} disabled={state.busy} data-testid="manage-claim-entry">
            Add this device to an existing wallet
          </button>
          {onClose ? <button onClick={onClose}>Close</button> : null}
        </div>
      </>
    );
  }

  // ── The set ──────────────────────────────────────────────────────────────────────
  return (
    <>
      <div className="card">
        <h2>Wallet</h2>
        {state.walletAddress ? (
          <>
            <div className="kv">
              <span className="k">Address</span>
              <span className="v" data-testid="settings-address">{state.walletAddress}</span>
            </div>
            {state.chains.map((row) => (
              <div className="kv" key={row.chainId} data-testid={`settings-chain-${row.chainId}`}>
                <span className="k">
                  {row.chainName} ({row.chainId})
                </span>
                <span className="v">
                  {row.deployed === null ? 'unreachable' : row.deployed ? `deployed · ${row.owners} owner(s)` : 'deploys with your first transaction'}
                </span>
              </div>
            ))}
          </>
        ) : (
          <p>{state.view === 'loading' ? 'Loading…' : 'No data yet.'}</p>
        )}
        {state.error ? <div className="error" data-testid="manage-error">{state.error}</div> : null}
      </div>

      {state.divergent ? (
        <div className="card" data-testid="manage-divergence">
          <h2>⚠ Owner sets differ between networks</h2>
          <p>
            The credentials that control this wallet are not the same on every network it is served on. This needs
            reconciliation — a change may not have reached every network yet. The list below is the set on{' '}
            {state.referenceChainName}.
          </p>
        </div>
      ) : null}

      {state.view === 'unreadable' ? (
        // WM-05: the set could not be read anywhere — say so; never render an empty list.
        <div className="card" data-testid="manage-unreadable">
          <h2>The owner set could not be read</h2>
          <p>
            None of the served networks could be reached, so what controls this wallet cannot be shown right now. This
            is a connectivity problem, not your credential list.
          </p>
          <div className="actions">
            <button onClick={() => void actions.load()}>Try again</button>
          </div>
        </div>
      ) : null}

      {state.walletAddress && state.view === 'set' && (
        <div className="card">
          <h2>Who can act on this wallet</h2>
          {state.chains.length > 1 && state.referenceChainName ? (
            <p>As recorded on {state.referenceChainName} — an owner change applies per network.</p>
          ) : null}
          {state.owners.map((row) => (
            <OwnerRowView
              key={row.ownerBytes}
              row={row}
              actions={actions}
              canRemove={state.owners.length > 1}
              onRemove={() => actions.startRemove(row)}
            />
          ))}
          {state.owners.length === 1 ? (
            <p data-testid="manage-last-owner-note">
              This is the only credential that can act on the wallet, so it cannot be removed — removing it would lock
              the wallet forever. Add another passkey or account first.
            </p>
          ) : null}
          {state.strays.map((stray) => (
            <div className="kv" key={stray.credentialId ?? stray.ownerBytes} data-testid="manage-stray-credential">
              <span className="k">{stray.name ?? `${(stray.credentialId ?? stray.fingerprint).slice(0, 12)}…`}</span>
              <span className="v">{stray.removedAt ? 'removed — no longer an owner' : 'NOT an owner of this wallet'}</span>
            </div>
          ))}
          {!state.deployed ? (
            <p>The wallet is not deployed on any served network yet — owner management becomes available with its first transaction.</p>
          ) : null}
        </div>
      )}

      {state.walletAddress && (
        <div className="card">
          <h2>Add a credential</h2>
          <div className="actions" style={{ flexDirection: 'column', paddingTop: 4 }}>
            <button
              className="primary"
              onClick={() => {
                setAddVariant('this-device');
                actions.startAddThisDevice();
              }}
              data-testid="manage-add-passkey"
              disabled={!state.deployed}
            >
              Add a passkey on this device
            </button>
            <button
              onClick={() => {
                setAddVariant('second-device');
                actions.startAddSecondDevice();
              }}
              data-testid="manage-add-device"
              disabled={!state.deployed}
            >
              Add a passkey on another device
            </button>
            <button onClick={() => actions.startAddAddress()} data-testid="manage-add-address" disabled={!state.deployed}>
              Add an Ethereum account
            </button>
          </div>
        </div>
      )}

      <div className="actions">
        {onClose ? (
          <button onClick={onClose} data-testid="manage-close">
            Done
          </button>
        ) : (
          <button className="danger" onClick={() => void actions.logout()} disabled={state.busy}>
            Log out (revoke session)
          </button>
        )}
      </div>
    </>
  );
}

function OwnerRowView({
  row,
  actions,
  canRemove,
  onRemove,
}: {
  row: OwnerRow;
  actions: ManagementController;
  canRemove: boolean;
  onRemove: () => void;
}) {
  const [renaming, setRenaming] = useState(false);
  const [name, setName] = useState(row.name ?? '');
  const [saving, setSaving] = useState(false);

  useEffect(() => setName(row.name ?? ''), [row.name]);

  const saveName = async () => {
    if (!row.credentialId) return;
    setSaving(true);
    try {
      await actions.rename(row.credentialId, name.trim() || null);
      setRenaming(false);
    } finally {
      setSaving(false);
    }
  };

  // WM-03/WM-09: identifiable without a name — kind, fingerprint, creation date, transports.
  const title = row.name ?? (row.kind === 'address' ? 'Ethereum account' : 'Passkey');
  const subtitle =
    row.kind === 'address'
      ? row.address
      : row.credentialId
        ? `passkey · added ${row.createdAt ? new Date(row.createdAt).toLocaleDateString() : 'unknown'}${row.transports?.length ? ` · ${row.transports.join('/')}` : ''}`
        : 'passkey · added outside this deployment'; // WM-04: never silently omitted

  return (
    <div style={{ borderBottom: '1px dashed var(--border)', padding: '8px 0' }} data-testid="manage-owner-row" data-fingerprint={row.fingerprint}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, alignItems: 'baseline' }}>
        <div>
          <b data-testid="manage-owner-name">{title}</b>{' '}
          {row.isCurrent ? (
            <span style={{ background: 'var(--pill)', borderRadius: 6, padding: '1px 6px', fontSize: 11 }} data-testid="manage-owner-current">
              this session
            </span>
          ) : null}
          <div style={{ color: 'var(--muted)', fontSize: 12, wordBreak: 'break-all' }}>{subtitle}</div>
        </div>
        <span className="v" style={{ fontFamily: 'ui-monospace, monospace', fontSize: 13 }} data-testid="manage-owner-fingerprint">
          {row.fingerprint}
        </span>
      </div>
      <div style={{ display: 'flex', gap: 8, marginTop: 6 }}>
        {row.credentialId ? (
          renaming ? (
            <>
              <input
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder="Name this credential"
                style={{ flex: 1, borderRadius: 8, border: '1px solid var(--border)', padding: '6px 8px', background: 'var(--bg)', color: 'var(--fg)' }}
                data-testid="manage-rename-input"
              />
              <button style={{ flex: 'none', padding: '6px 10px', fontSize: 13 }} onClick={() => void saveName()} disabled={saving} data-testid="manage-rename-save">
                Save
              </button>
            </>
          ) : (
            <button style={{ flex: 'none', padding: '6px 10px', fontSize: 13 }} onClick={() => setRenaming(true)} data-testid="manage-rename">
              Rename
            </button>
          )
        ) : null}
        <button
          style={{ flex: 'none', padding: '6px 10px', fontSize: 13 }}
          className="danger"
          onClick={onRemove}
          disabled={!canRemove}
          title={canRemove ? undefined : 'The last remaining credential cannot be removed'}
          data-testid="manage-remove"
        >
          Remove
        </button>
      </div>
    </div>
  );
}
