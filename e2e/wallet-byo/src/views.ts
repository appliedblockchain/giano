import type { SponsorshipRefusalReason } from '@appliedblockchain/giano-wallet-core';
import { hexToString, isHex } from 'viem';
import type { PendingRequest } from './requests';
import type { SponsorshipPreflight } from './runtime';

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

/**
 * Who can actually resolve each refusal, in the BYO UI's own words.
 *
 * A user meeting any of these cannot fix it themselves — they can neither top up an application's
 * fee balance nor edit its allowlist — so a refusal that stops at "this cannot be sponsored"
 * leaves them retrying something that will never work. Keyed by the machine-readable reason for
 * the same purpose as the stock wallet's copy map, and with a fallback because an unrecognised
 * reason means the service is ahead of this build.
 */
const NEXT_STEP: Record<SponsorshipRefusalReason, string> = {
  'sponsorship-disabled': 'Nothing you can change will affect this — tell the app’s team if you expected it to be free.',
  'no-sponsorship-config': 'The app’s developers have not set fee coverage up yet.',
  'contract-not-allowed': 'The app’s developers need to allow this contract before its fees can be covered.',
  'function-not-allowed': 'The app’s developers need to allow this action before its fees can be covered.',
  'wallet-management-not-sponsored': 'Only the app’s team can turn this back on — tell them you could not change your wallet.',
  'cost-exceeds-cap': 'Fees move around, so this may work later — raising the limit is the app team’s to do.',
  'insufficient-balance': 'The app’s operators need to top up its fee balance. Nothing is wrong with your wallet.',
  'tenant-in-deficit': 'The app’s operators need to settle and top up its fee balance.',
  'not-your-wallet': 'Reconnect the app and try again.',
  'chain-or-entrypoint-mismatch': 'The app is pointed at a different network; its developers need to correct that.',
  'temporarily-unavailable': 'This is usually brief — try again in a moment.',
};

/**
 * The pre-approval refusal, in the BYO UI's own idiom.
 *
 * Deliberately worded differently from the stock wallet — a tenant writes its own copy — but with
 * the same three obligations: the machine-readable reason is exposed for the test to assert, the
 * refusal names who can act on it, and no confirm button is rendered at all. Offering one and
 * failing afterwards would mean asking for a passkey ceremony that could never have succeeded.
 */
function sponsorshipNotice(preflight: SponsorshipPreflight): HTMLElement | null {
  if (preflight.state === 'sponsored') {
    return el('div', { className: 'idle', dataset: { testid: 'byo-sponsorship-covered' } }, 'Fees for this transaction are covered by the app.');
  }
  if (preflight.state === 'not-applicable') return null;

  const reason = preflight.state === 'refused' ? preflight.reason : 'temporarily-unavailable';
  return el(
    'div',
    { className: 'payload', dataset: { testid: 'byo-sponsorship-refusal', reason } },
    preflight.state === 'refused'
      ? `This app will not cover the fee for this transaction (${preflight.reason}).`
      : 'Fee coverage is temporarily unavailable — try again shortly.',
    el('p', { dataset: { testid: 'byo-sponsorship-refusal-action' } }, NEXT_STEP[reason] ?? NEXT_STEP['temporarily-unavailable']),
  );
}

export function render(
  root: HTMLElement,
  pending: PendingRequest | null,
  busy: boolean,
  preflight: SponsorshipPreflight | null = { state: 'not-applicable' },
): void {
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
    );

    if (preflight === null) {
      root.append(el('div', { className: 'idle', dataset: { testid: 'byo-sponsorship-checking' } }, 'Checking fee coverage…'));
      root.append(el('div', { className: 'row' }, el('button', { className: 'secondary', textContent: 'Decline', onclick: () => pending.reject() })));
      return;
    }

    const notice = sponsorshipNotice(preflight);
    if (notice) root.append(notice);

    if (preflight.state === 'refused' || preflight.state === 'unavailable') {
      // No confirm button, and therefore no passkey prompt.
      root.append(el('div', { className: 'row' }, el('button', { className: 'secondary', textContent: 'Close', onclick: () => pending.reject() })));
      return;
    }

    root.append(buttons('Confirm', 'byo-confirm'));
    return;
  }

  root.append(
    el('h2', {}, 'Signature requested'),
    originBadge(pending.dappOrigin),
    el('pre', { className: 'payload' }, describeSignPayload(pending.method, pending.params)),
    buttons('Sign it', 'byo-sign'),
  );
}
