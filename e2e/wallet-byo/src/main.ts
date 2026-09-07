import {
  createWalletHost,
  createWalletRuntimes,
  type PendingRequest,
  type SponsorshipPreflight,
  type TransactionRequest,
} from '@appliedblockchain/giano-wallet-kit';
import { walletConfig } from './config';
import { renderManage } from './manage';
import { render } from './views';

/**
 * A tenant-built ("bring your own") wallet UI: framework-free reference implementation of
 * a wallet origin ON THE KIT'S CORE (WK-31) — the same consent semantics as the stock
 * wallet-web, a visibly different everything else. Everything below the pixels — config
 * validation, per-chain runtimes, the transport host, the consent queue, the management
 * state machine — is `@appliedblockchain/giano-wallet-kit`; this file only renders.
 */

const config = walletConfig();
const runtimes = createWalletRuntimes(config);
const host = createWalletHost({ runtimes, config, walletVersion: '0.1.0-byo' });
const root = document.getElementById('view')!;

let busy = false;
let managing = false;
/** null while the sponsorship pre-flight is still in the air; nothing is approvable until then. */
let preflight: SponsorshipPreflight | null = { state: 'not-applicable' };

const rerender = () => {
  if (managing) return; // the management view owns the root while it is open
  const pending = host.requests.current;
  render(root, pending && withBusy(pending), busy, preflight);
};

/** Marks the popup busy after approval, while the provider runs the ceremony. */
function withBusy(pending: PendingRequest): PendingRequest {
  return {
    ...pending,
    approve: () => {
      busy = true;
      preflight = { state: 'not-applicable' };
      pending.approve();
      rerender();
    },
  };
}

/**
 * Runs the pre-flight when a transaction request arrives, before anything approvable is rendered.
 * The reason is written to the console as well as shown, because a transient notice is gone by the
 * time anyone investigates — and the reason is what separates "this app is misconfigured" from
 * "this app is out of credit".
 */
async function runSponsorshipPreflight(pending: PendingRequest): Promise<void> {
  const tx = (Array.isArray(pending.params) ? pending.params[0] : pending.params) as TransactionRequest | undefined;
  preflight = null;
  rerender();

  const result = await pending.runtime.checkSponsorship(tx ?? {});
  if (host.requests.current !== pending) return; // the request resolved while we were checking
  preflight = result;
  if (result.state === 'refused') {
    console.error('[giano-byo] sponsorship refused', { reason: result.reason, message: result.message, ruleResults: result.ruleResults });
  } else if (result.state === 'unavailable') {
    console.error('[giano-byo] sponsorship unavailable', { message: result.message });
  } else if (result.state === 'sponsored') {
    console.info('[giano-byo] sponsorship available — fees covered by the app');
  }
  rerender();
}

function openManage(onClose?: () => void) {
  managing = true;
  renderManage(root, {
    runtimes,
    config,
    onClose: onClose
      ? () => {
          managing = false;
          onClose();
          rerender();
        }
      : undefined,
  });
}

host.requests.subscribe((pending) => {
  // busy survives the approve-triggered null notification: the ceremony is still running.
  if (pending) busy = false;
  // WM-54/WM-60: the BYO wallet mounts its own management view for the manage request,
  // against the same kit (and therefore the same API) as the stock UI. Approving the
  // request when the view closes returns nothing to the dApp (WM-40).
  if (pending?.kind === 'manage') {
    openManage(pending.approve);
    return;
  }
  preflight = { state: 'not-applicable' };
  if (pending?.kind === 'transaction') void runSponsorshipPreflight(pending);
  rerender();
});

if (window.opener) {
  rerender();
} else {
  // Opened directly (WM-56): the standalone entry is the management view, with the same
  // capabilities the popup path offers.
  openManage();
}
host.start();
window.addEventListener('beforeunload', () => host.stop());
