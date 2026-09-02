import {
  createManagementController,
  type ChainProgress,
  type ManagementController,
  type ManagementFlow,
  type ManagementState,
  type WalletConfig,
  type WalletRuntimes,
} from '@appliedblockchain/giano-wallet-kit';

/**
 * Bring-your-own-UI wallet management (WM-60, WM-61): viewing, adding and removing
 * credentials, rendered over the kit's headless controller (WK-31) — the same state
 * machine the stock interface renders with React, drawn here with plain DOM and
 * deliberately different labels so the e2e suite can prove which UI ran the flow.
 */

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Partial<HTMLElementTagNameMap[K]> & { dataset?: Record<string, string> } = {},
  ...children: (Node | string)[]
) {
  const node = document.createElement(tag);
  const { dataset, ...rest } = props;
  Object.assign(node, rest);
  if (dataset) for (const [key, value] of Object.entries(dataset)) node.dataset[key] = value;
  node.append(...children);
  return node;
}

export function renderManage(root: HTMLElement, options: { runtimes: WalletRuntimes; config: WalletConfig; onClose?: () => void }): void {
  const { runtimes, config, onClose } = options;
  const mgmt: ManagementController = createManagementController({ runtimes, config });

  const close = onClose
    ? () => {
        unsubscribe();
        mgmt.destroy();
        onClose();
      }
    : undefined;

  const progressList = (rows: ChainProgress[]) =>
    el(
      'div',
      { dataset: { testid: 'byo-manage-progress' } },
      ...rows.map((row) =>
        el(
          'div',
          { className: 'origin', dataset: { testid: `byo-manage-progress-${row.chainId}`, state: row.state } },
          `${row.chainName} (${row.chainId}): ${row.state}${row.detail ? ` — ${row.detail}` : ''}`,
        ),
      ),
    );

  function renderFlow(flow: ManagementFlow): void {
    if (flow.type === 'refused') {
      root.append(
        el('h2', {}, 'This change is not covered'),
        el('div', { className: 'payload', dataset: { testid: 'byo-manage-refused', reason: flow.reason } }, flow.message),
        el('div', { className: 'row' }, el('button', { className: 'secondary', textContent: 'Back', onclick: () => flow.back() })),
      );
      return;
    }

    if (flow.type === 'add') {
      if (flow.step === 'preparing') {
        root.append(el('h2', {}, 'Add a key to this wallet'), el('div', { className: 'idle' }, 'Creating the passkey…'));
        return;
      }
      if (flow.step === 'confirm-fingerprint') {
        root.append(
          el('h2', {}, 'Add a key to this wallet'),
          el('div', { className: 'idle' }, 'A new passkey was created on this device. Its fingerprint:'),
          el('pre', { className: 'payload', dataset: { testid: 'byo-manage-fingerprint' } }, flow.fingerprint),
          el(
            'div',
            { className: 'row' },
            el('button', { className: 'secondary', textContent: 'Abort', onclick: () => flow.decline() }),
            el('button', {
              textContent: 'Make it an owner',
              dataset: { testid: 'byo-manage-add-approve' },
              onclick: () => {
                flow.setName(`BYO backup · ${new Date().toLocaleDateString()}`);
                flow.approve();
              },
            }),
          ),
        );
        return;
      }
      if (flow.step === 'applying') {
        root.append(el('h2', {}, 'Adding the key…'), progressList(flow.chains));
        return;
      }
      if (flow.step === 'done') {
        root.append(
          el('h2', {}, flow.ok ? 'Key added' : 'Key not fully added'),
          progressList(flow.chains),
          flow.refusal ? el('div', { className: 'payload' }, `${flow.refusal.reason}: ${flow.refusal.message}`) : '',
          el('div', { className: 'row' }, el('button', { textContent: 'Back to keys', dataset: { testid: 'byo-manage-flow-done' }, onclick: () => mgmt.dismissFlow() })),
        );
        return;
      }
      // 'error' (plus the cross-device steps this minimal UI does not start)
      root.append(
        el('h2', {}, 'Key not added'),
        el('div', { className: 'payload' }, flow.step === 'error' ? flow.message : `unexpected step: ${flow.step}`),
        el('div', { className: 'row' }, el('button', { textContent: 'Back to keys', dataset: { testid: 'byo-manage-flow-done' }, onclick: () => mgmt.dismissFlow() })),
      );
      return;
    }

    if (flow.type === 'remove') {
      if (flow.step === 'confirm') {
        const { owner } = flow;
        root.append(
          el('h2', {}, 'Remove this key?'),
          // WM-32: identified by more than a name.
          el('div', { className: 'idle' }, `${owner.name ?? (owner.kind === 'address' ? 'Ethereum account' : 'Passkey')} · fingerprint ${owner.fingerprint}`),
          el('pre', { className: 'payload', dataset: { testid: 'byo-manage-remove-identifier' } }, owner.kind === 'address' ? (owner.address as string) : owner.ownerBytes),
          flow.endsThisSession
            ? el('div', { className: 'payload', dataset: { testid: 'byo-manage-remove-current' } }, 'This is the key this session is using — removing it signs you out here (WM-30).')
            : '',
          el(
            'div',
            { className: 'row' },
            el('button', { className: 'secondary', textContent: 'Keep it', onclick: () => flow.cancel() }),
            el('button', { textContent: 'Remove it', dataset: { testid: 'byo-manage-remove-approve' }, onclick: () => flow.approve() }),
          ),
        );
        return;
      }
      if (flow.step === 'applying') {
        root.append(el('h2', {}, 'Removing…'), progressList(flow.chains));
        return;
      }
      if (flow.step === 'done') {
        root.append(
          el('h2', {}, flow.ok ? 'Key removed' : 'Key not fully removed'),
          progressList(flow.chains),
          flow.refusal ? el('div', { className: 'payload' }, `${flow.refusal.reason}: ${flow.refusal.message}`) : '',
          flow.endedSession ? el('div', { className: 'payload', dataset: { testid: 'byo-manage-signed-out' } }, 'That was this session’s key — you are signed out.') : '',
          el(
            'div',
            { className: 'row' },
            el('button', { textContent: flow.endedSession ? 'OK' : 'Back to keys', dataset: { testid: 'byo-manage-flow-done' }, onclick: () => mgmt.dismissFlow() }),
          ),
        );
        return;
      }
      root.append(
        el('h2', {}, 'Key not removed'),
        el('div', { className: 'payload' }, flow.step === 'error' ? flow.message : `unexpected step: ${flow.step}`),
        el('div', { className: 'row' }, el('button', { textContent: 'Back to keys', dataset: { testid: 'byo-manage-flow-done' }, onclick: () => mgmt.dismissFlow() })),
      );
      return;
    }

    // The minimal BYO surface starts neither the address nor the claim flow; render a way out.
    root.append(
      el('h2', {}, 'Not available here'),
      el('div', { className: 'row' }, el('button', { textContent: 'Back to keys', dataset: { testid: 'byo-manage-flow-done' }, onclick: () => mgmt.dismissFlow() })),
    );
  }

  function render(state: ManagementState): void {
    root.replaceChildren();

    if (mgmt.flow) {
      renderFlow(mgmt.flow);
      return;
    }

    // Signed out (WM-57): offer sign-in rather than failing.
    if (state.view === 'signed-out') {
      root.append(
        el('h2', {}, 'Wallet keys'),
        el('div', { className: 'idle' }, 'Unlock your BYO wallet to see and change what can act on it.'),
        state.error ? el('div', { className: 'payload', dataset: { testid: 'byo-manage-error' } }, state.error) : '',
        el(
          'div',
          { className: 'row' },
          close ? el('button', { className: 'secondary', textContent: 'Close', onclick: close }) : '',
          el('button', {
            textContent: state.busy ? 'Waiting for passkey…' : 'Unlock with passkey',
            disabled: state.busy,
            dataset: { testid: 'byo-manage-unlock' },
            onclick: () => void mgmt.signIn(),
          }),
        ),
      );
      return;
    }

    // The set.
    const children: (Node | string)[] = [el('h2', {}, 'Wallet keys')];
    if (state.walletAddress) {
      children.push(el('div', { className: 'origin', dataset: { testid: 'byo-manage-address' } }, state.walletAddress));
    }
    if (state.error) {
      children.push(el('div', { className: 'payload', dataset: { testid: 'byo-manage-error' } }, state.error));
    }

    if (state.view === 'unreadable') {
      // WM-05: say the chain could not be read — never render an empty set as fact.
      const detail = state.chains.find((chain) => chain.error)?.error ?? 'unknown error';
      children.push(
        el('div', { className: 'payload', dataset: { testid: 'byo-manage-unreadable' } }, `The network could not be read, so the key list cannot be shown: ${detail}`),
        el('div', { className: 'row' }, el('button', { textContent: 'Retry', onclick: () => void mgmt.load() })),
      );
    } else {
      for (const owner of state.owners) {
        children.push(
          el(
            'div',
            { className: 'origin', dataset: { testid: 'byo-manage-owner', fingerprint: owner.fingerprint } },
            el('b', {}, owner.name ?? (owner.kind === 'address' ? 'Ethereum account' : 'Passkey (added elsewhere)')),
            ` · ${owner.fingerprint}`,
            owner.isCurrent ? el('span', { dataset: { testid: 'byo-manage-owner-current' } }, ' · this session') : '',
            el('button', {
              className: 'secondary',
              textContent: 'Remove',
              disabled: state.owners.length <= 1,
              dataset: { testid: 'byo-manage-remove' },
              onclick: () => mgmt.startRemove(owner),
            }),
          ),
        );
      }
      if (state.owners.length === 1) {
        children.push(
          el('div', { className: 'idle', dataset: { testid: 'byo-manage-last-owner' } }, 'Your only key cannot be removed — that would lock the wallet forever. Add another key first.'),
        );
      }
      // WM-04: registry rows the chain does not back are shown as NOT owners.
      for (const stray of state.strays) {
        children.push(
          el(
            'div',
            { className: 'origin', dataset: { testid: 'byo-manage-stray' } },
            `${stray.name ?? (stray.credentialId ?? stray.fingerprint).slice(0, 12)} · ${stray.removedAt ? 'removed — no longer an owner' : 'NOT an owner of this wallet'}`,
          ),
        );
      }
      children.push(
        el(
          'div',
          { className: 'row' },
          el('button', { textContent: 'Add a key on this device', dataset: { testid: 'byo-manage-add' }, onclick: () => mgmt.startAddThisDevice() }),
        ),
      );
    }

    if (close) {
      children.push(el('div', { className: 'row' }, el('button', { className: 'secondary', textContent: 'Close', dataset: { testid: 'byo-manage-close' }, onclick: close })));
    }
    root.append(...children);
  }

  const unsubscribe = mgmt.subscribe(render);
  void mgmt.load();
}
