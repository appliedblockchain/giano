import type { SponsorshipRefusalReason } from '@appliedblockchain/giano-wallet-core';

/**
 * What a refusal says to the person in front of the screen.
 *
 * One map, keyed by the machine-readable reason, because "this app doesn't support that contract"
 * and "this app has run out of gas credit" are genuinely different sentences and a user who is
 * shown the wrong one will take the wrong action. The wallet never renders a reason code, and
 * never keys behaviour off the server's prose.
 *
 * `action` is not optional in spirit: a user meeting any of these cannot resolve it themselves —
 * they cannot fund an application's fee balance or edit its allowlist — so every refusal has to
 * name the party who can, or it leaves them retrying something that will never work. The point of
 * typed refusals is that the user can tell "wait and retry" from "the app's team has to fix this".
 */
type Copy = { title: string; body: string; action: string; retryable: boolean };

const COPY: Record<SponsorshipRefusalReason, Copy> = {
  'sponsorship-disabled': {
    title: 'This app does not cover transaction fees',
    body: 'Fee sponsorship is switched off for this application, so this transaction cannot be sent for free.',
    action: 'Nothing you can change will affect this — let the application’s team know if you expected it to work.',
    retryable: false,
  },
  'no-sponsorship-config': {
    title: 'Fee sponsorship is not set up',
    body: 'This application has not configured which transactions it will cover the fees for.',
    action: 'The application’s developers need to set this up.',
    retryable: false,
  },
  'contract-not-allowed': {
    title: 'This app does not cover fees for this contract',
    body: 'The transaction targets a contract this application has not agreed to sponsor.',
    action: 'If you expected this to work, the application’s developers need to allow this contract.',
    retryable: false,
  },
  'function-not-allowed': {
    title: 'This app does not cover fees for this action',
    body: 'The contract is sponsored, but not this particular function on it.',
    action: 'If you expected this to work, the application’s developers need to allow this function.',
    retryable: false,
  },
  'wallet-management-not-sponsored': {
    title: 'Wallet changes are not covered',
    body:
      'Changes to the wallet itself — adding or removing a passkey, or recovery — are covered by default, but this ' +
      'application has switched that off.',
    action: 'Only the application’s team can turn this back on. Let them know you could not add a passkey.',
    retryable: false,
  },
  'cost-exceeds-cap': {
    title: 'This transaction costs too much to be covered',
    body: 'The network fee for this transaction is above the limit this application covers per transaction.',
    action:
      'Network fees change over time, so this may work later — but raising the limit is the application team’s to do.',
    retryable: false,
  },
  'insufficient-balance': {
    title: 'This app has run out of fee credit',
    body: 'The application has no remaining balance to cover transaction fees.',
    action: 'The application’s operators need to top it up. This is not a problem with your wallet.',
    retryable: true,
  },
  'tenant-in-deficit': {
    title: 'This app has run out of fee credit',
    body: 'The application’s fee balance is overdrawn and needs to be settled before further transactions can be covered.',
    action: 'The application’s operators need to top it up.',
    retryable: true,
  },
  'not-your-wallet': {
    title: 'This transaction is not for your wallet',
    body: 'The transaction names a different wallet from the one you are signed in with.',
    action: 'Try reconnecting the application.',
    retryable: false,
  },
  'chain-or-entrypoint-mismatch': {
    title: 'This transaction is for a different network',
    body: 'The application asked to send this transaction on a network this wallet does not serve.',
    action: 'This is a mismatch in the application’s configuration; its developers need to correct it.',
    retryable: false,
  },
  'temporarily-unavailable': {
    title: 'Fee sponsorship is temporarily unavailable',
    body: 'The service that covers transaction fees could not be reached.',
    action: 'This is usually brief — try again in a moment.',
    retryable: true,
  },
};

export function refusalCopy(reason: SponsorshipRefusalReason): Copy {
  // An unrecognised reason means the service is ahead of this build. Falling back to the outage
  // copy is the safe choice: it is the one message that does not make a claim about *why*.
  return COPY[reason] ?? COPY['temporarily-unavailable'];
}
