import { TransportHost } from '@appliedblockchain/giano-wallet-transport';
import { CONFIG } from './config';
import { createRequestStore, toRpcError } from './requests';
import { createWalletRuntime } from './runtime';
import { render } from './views';

/**
 * A tenant-built ("bring your own") wallet UI: framework-free reference implementation
 * of everything a wallet origin must do — the same consent semantics as the stock
 * wallet-web, a visibly different everything else.
 */

const CONSENT_METHODS = new Set(['eth_sendTransaction', 'personal_sign', 'eth_sign', 'eth_signTypedData_v4']);

const runtime = createWalletRuntime();
const requests = createRequestStore();
const root = document.getElementById('view')!;

let inflight = 0;
const rerender = () => render(root, requests.current, inflight > 0);

const transport = new TransportHost({
  walletVersion: '0.1.0-byo',
  // fail closed: only the tenant's own dApp origins may drive this wallet
  allowedOrigins: CONFIG.allowedDappOrigins,
  onRequest: async (method, params, context) => {
    const needsConsent = method === 'eth_requestAccounts' || CONSENT_METHODS.has(method);
    // A signing/tx request can land on a freshly (re)opened popup whose in-memory
    // account was lost when the previous popup closed — silently rebuild it from the
    // persisted session before asking for consent (no extra passkey prompt).
    if (CONSENT_METHODS.has(method) && !runtime.provider.getSmartAccount()) {
      await runtime.provider.request({ method: 'giano_restoreAccount' } as never).catch(() => undefined);
    }
    if (needsConsent) {
      await requests.requestConsent({
        kind: method === 'eth_requestAccounts' ? 'connect' : method === 'eth_sendTransaction' ? 'transaction' : 'sign',
        method,
        params,
        dappOrigin: context.dappOrigin,
      });
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

// relay provider events (accountsChanged, chainChanged, disconnect) to the dApp
for (const event of ['accountsChanged', 'chainChanged', 'disconnect'] as const) {
  runtime.provider.on(event, (data: unknown) => transport.sendEvent(event, data));
}

requests.subscribe(() => rerender());
rerender();
transport.start();
window.addEventListener('beforeunload', () => transport.stop());
