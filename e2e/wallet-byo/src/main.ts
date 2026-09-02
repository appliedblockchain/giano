import { RPC_ERRORS, TransportHost, TransportRpcError } from '@appliedblockchain/giano-wallet-transport';
import { CONFIG } from './config';
import { renderManage } from './manage';
import { createRequestStore, toRpcError } from './requests';
import { createWalletRuntimes, type WalletRuntime } from './runtime';
import { render } from './views';

/**
 * A tenant-built ("bring your own") wallet UI: framework-free reference implementation
 * of everything a wallet origin must do — the same consent semantics as the stock
 * wallet-web, a visibly different everything else.
 */

const CONSENT_METHODS = new Set(['eth_sendTransaction', 'personal_sign', 'eth_sign', 'eth_signTypedData_v4']);

const runtimes = createWalletRuntimes();
const requests = createRequestStore();
const root = document.getElementById('view')!;
const wiredChains = new Set<number>();

let inflight = 0;
/** null while the sponsorship pre-flight is still in the air; nothing is approvable until then. */
let preflight: import('./runtime').SponsorshipPreflight | null = { state: 'not-applicable' };
const rerender = () => render(root, requests.current, inflight > 0, preflight);

/**
 * Runs the pre-flight when a transaction request arrives, before anything approvable is rendered.
 * The reason is written to the console as well as shown, because a transient notice is gone by the
 * time anyone investigates — and the reason is what separates "this app is misconfigured" from
 * "this app is out of credit".
 */
async function runSponsorshipPreflight(runtime: WalletRuntime, params: unknown): Promise<void> {
  const tx = (Array.isArray(params) ? params[0] : params) as import('./runtime').TransactionRequest | undefined;
  preflight = null;
  rerender();

  const result = await runtime.checkSponsorship(tx ?? {});
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

const transport = new TransportHost({
  walletVersion: '0.1.0-byo',
  // fail closed: only the tenant's own dApp origins may drive this wallet
  allowedOrigins: CONFIG.allowedDappOrigins,
  // the closed list the handshake negotiates against (MC-03)
  servedChainIds: runtimes.servedChainIds,
  onRequest: async (method, params, context) => {
    // WM-54/WM-60: the BYO wallet handles the management method itself, against the same
    // API as the stock UI. No parameters in (WM-39), nothing out (WM-40).
    if (method === 'giano_openWalletManagement') {
      const params_ = params as unknown[] | undefined;
      if (params_ !== undefined && params_ !== null && !(Array.isArray(params_) && params_.length === 0)) {
        throw new TransportRpcError(RPC_ERRORS.UNSUPPORTED_METHOD, 'the management interface accepts no parameters from the application');
      }
      await new Promise<void>((resolve) => renderManage(root, { runtimes, onClose: resolve }));
      rerender();
      return null;
    }

    // the session's negotiated chain picks the runtime — same shape as the stock wallet (MC-43)
    const runtime = runtimes.runtimeFor(context.chainId);
    if (!wiredChains.has(context.chainId)) {
      wiredChains.add(context.chainId);
      // relay provider events (accountsChanged, chainChanged, disconnect) to the dApp
      for (const event of ['accountsChanged', 'chainChanged', 'disconnect'] as const) {
        runtime.provider.on(event, (data: unknown) => transport.sendEvent(event, data));
      }
    }
    const needsConsent = method === 'eth_requestAccounts' || CONSENT_METHODS.has(method);
    // A signing/tx request can land on a freshly (re)opened popup whose in-memory
    // account was lost when the previous popup closed — silently rebuild it from the
    // persisted session before asking for consent (no extra passkey prompt).
    if (CONSENT_METHODS.has(method) && !runtime.provider.getSmartAccount()) {
      await runtime.provider.request({ method: 'giano_restoreAccount' } as never).catch(() => undefined);
    }
    if (needsConsent) {
      const consent = requests.requestConsent({
        kind: method === 'eth_requestAccounts' ? 'connect' : method === 'eth_sendTransaction' ? 'transaction' : 'sign',
        method,
        params,
        dappOrigin: context.dappOrigin,
        chainName: runtime.chainName,
      });
      // Started alongside the consent prompt rather than before it, so the request is on screen
      // while the check runs — but the confirm button does not appear until it has answered.
      if (method === 'eth_sendTransaction') void runSponsorshipPreflight(runtime, params);
      await consent;
      preflight = { state: 'not-applicable' };
    }
    inflight += 1;
    rerender();
    try {
      return await runtime.provider.request({ method, params } as never);
    } catch (error) {
      throw toRpcError(error);
    } finally {
      inflight -= 1;
      rerender();
    }
  },
});

requests.subscribe(() => rerender());
if (window.opener) {
  rerender();
} else {
  // Opened directly (WM-56): the standalone entry is the management view, with the same
  // capabilities the popup path offers.
  renderManage(root, { runtimes });
}
transport.start();
window.addEventListener('beforeunload', () => transport.stop());
