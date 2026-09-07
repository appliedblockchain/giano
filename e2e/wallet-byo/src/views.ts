import { hexToString, isHex } from 'viem';
import type { PendingRequest } from './requests';

/**
 * Plain-DOM views — what wallet-web renders with React, a BYO UI can render however it
 * likes. Labels are deliberately different from the stock UI ("Unlock with passkey",
 * "Confirm"/"Decline", "Sign it") so the e2e suite can prove a different UI ran the flow.
 */

function el<K extends keyof HTMLElementTagNameMap>(tag: K, props: Partial<HTMLElementTagNameMap[K]> & { dataset?: Record<string, string> } = {}, ...children: (Node | string)[]) {
  const node = document.createElement(tag);
  const { dataset, ...rest } = props;
  Object.assign(node, rest);
  if (dataset) for (const [k, v] of Object.entries(dataset)) node.dataset[k] = v;
  node.append(...children);
  return node;
}

const originBadge = (dappOrigin: string) => el('div', { className: 'origin', dataset: { testid: 'dapp-origin' } }, dappOrigin);

function describeSignPayload(method: string, params: unknown): string {
  const list = Array.isArray(params) ? params : [];
  const raw = method === 'personal_sign' ? list[0] : method === 'eth_sign' ? list[1] : list[1];
  if (method === 'eth_signTypedData_v4' && typeof raw === 'string') {
    try {
      return JSON.stringify(JSON.parse(raw), null, 2);
    } catch {
      return raw;
    }
  }
  if (typeof raw === 'string' && isHex(raw)) {
    try {
      return hexToString(raw);
    } catch {
      return raw;
    }
  }
  return typeof raw === 'string' ? raw : JSON.stringify(raw);
}

function describeTransaction(params: unknown): string {
  const tx = (Array.isArray(params) ? params[0] : params) as { to?: string; value?: string; data?: string } | undefined;
  return [`to:    ${tx?.to ?? '(contract creation)'}`, `value: ${tx?.value ?? '0x0'}`, `data:  ${tx?.data ?? '0x'}`].join('\n');
}

export function render(root: HTMLElement, pending: PendingRequest | null, busy: boolean): void {
  root.replaceChildren();

  if (!pending) {
    root.append(el('div', { className: 'idle' }, busy ? 'Working — follow your passkey prompt…' : 'Waiting for a request from the connected app…'));
    return;
  }

  const buttons = (approveLabel: string, approveTestId: string) =>
    el(
      'div',
      { className: 'row' },
      el('button', { className: 'secondary', textContent: 'Decline', onclick: () => pending.reject() }),
      el('button', { textContent: approveLabel, dataset: { testid: approveTestId }, onclick: () => pending.approve() }),
    );

  if (pending.kind === 'connect') {
    root.append(
      el('h2', {}, 'Connection request'),
      originBadge(pending.dappOrigin),
      el('div', { className: 'idle' }, 'Unlock your BYO wallet (or create one) with a passkey.'),
      buttons('Unlock with passkey', 'byo-connect'),
    );
    return;
  }

  if (pending.kind === 'transaction') {
    root.append(
      el('h2', { dataset: { testid: 'byo-tx' } }, 'Confirm transaction'),
      originBadge(pending.dappOrigin),
      el('pre', { className: 'payload' }, describeTransaction(pending.params)),
      buttons('Confirm', 'byo-confirm'),
    );
    return;
  }

  root.append(
    el('h2', {}, 'Signature requested'),
    originBadge(pending.dappOrigin),
    el('pre', { className: 'payload' }, describeSignPayload(pending.method, pending.params)),
    buttons('Sign it', 'byo-sign'),
  );
}
