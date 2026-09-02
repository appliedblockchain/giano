import { RPC_ERRORS, TransportHost, TransportRpcError } from '@appliedblockchain/giano-wallet-transport';
import type { WalletConfig } from './config';
import { createRequestStore, toRpcError, type RequestStore } from './requests';
import type { WalletRuntime, WalletRuntimes } from './wallet';

const CONSENT_METHODS = new Set(['eth_sendTransaction', 'personal_sign', 'eth_sign', 'eth_signTypedData_v4']);

export type WalletHost = {
  transport: TransportHost;
  requests: RequestStore;
  getDappOrigin: () => string | null;
};

/**
 * Wires the popup transport to the Giano provider with a consent gate:
 * - eth_requestAccounts → Connect view (create wallet or sign in with a passkey)
 * - eth_sendTransaction → ReviewTransaction view
 * - personal_sign / eth_sign / eth_signTypedData_v4 → SignMessage view
 * - everything else (read paths) forwards straight to the provider
 * All signing and credential work happens HERE, on the wallet origin — the dApp only
 * ever sees postMessage RPC.
 *
 * The chain is negotiated once per transport session, in the handshake (S1): every request
 * on the session is served by that chain's runtime, resolved lazily on first use (MC-44),
 * and there is no path by which a request reaches a different chain's runtime.
 */
export function createWalletHost(runtimes: WalletRuntimes, config: WalletConfig, walletVersion: string): WalletHost {
  const requests = createRequestStore();

  // Event relay is wired per runtime, once, when a session first touches that chain.
  const wiredChains = new Set<number>();
  let transport: TransportHost;
  const runtimeForSession = (chainId: number): WalletRuntime => {
    const runtime = runtimes.runtimeFor(chainId);
    if (!wiredChains.has(chainId)) {
      wiredChains.add(chainId);
      // relay provider events (accountsChanged, chainChanged, disconnect) to the dApp
      for (const event of ['accountsChanged', 'chainChanged', 'disconnect'] as const) {
        runtime.provider.on(event, (data: unknown) => transport.sendEvent(event, data));
      }
    }
    return runtime;
  };

  transport = new TransportHost({
    walletVersion,
    allowedOrigins: config.allowedDappOrigins,
    // The closed list the handshake negotiates against (MC-03): a dApp naming a chain
    // outside it is refused before any request — or passkey ceremony (MC-85) — happens.
    servedChainIds: [...runtimes.servedChainIds],
    onRequest: async (method, params, context) => {
      // MC-14: chain switching is refused explicitly with EIP-1193 4200 — never silently
      // ignored, never answered by the read path, never appearing to succeed. A dApp that
      // wants another chain constructs a provider for it (D1).
      if (method === 'wallet_switchEthereumChain' || method === 'wallet_addEthereumChain') {
        throw new TransportRpcError(
          RPC_ERRORS.UNSUPPORTED_METHOD,
          'Giano binds one chain per session; connect a provider constructed for the target chain',
        );
      }

      const runtime = runtimeForSession(context.chainId);

      // WM-54/WM-55: the application's ONE management affordance — open the view. It
      // accepts no parameters (WM-39: nothing pre-filled, nothing preselected) and
      // returns nothing (WM-40: no owner set, no names, no outcome go back to the dApp).
      if (method === 'giano_openWalletManagement') {
        const params_ = params as unknown[] | undefined;
        if (params_ !== undefined && params_ !== null && !(Array.isArray(params_) && params_.length === 0)) {
          throw new TransportRpcError(RPC_ERRORS.UNSUPPORTED_METHOD, 'the management interface accepts no parameters from the application');
        }
        await requests.requestConsent({
          kind: 'manage',
          method,
          params: undefined,
          dappOrigin: context.dappOrigin,
          chainId: runtime.chainId,
          chainName: runtime.chainName,
          runtime,
        });
        return null;
      }

      const needsConsent = method === 'eth_requestAccounts' || CONSENT_METHODS.has(method);
      // A signing/tx request can land on a freshly (re)opened popup whose in-memory
      // account was lost when the previous popup closed. Silently rebuild it from the
      // persisted session before asking for consent — no extra passkey prompt; the
      // single ceremony still happens when the operation is actually signed. If it
      // can't be restored, the provider will surface "Giano not connected" and the
      // dApp must reconnect via eth_requestAccounts.
      if (CONSENT_METHODS.has(method) && !runtime.provider.getSmartAccount()) {
        await runtime.provider.request({ method: 'giano_restoreAccount' } as never).catch(() => undefined);
      }
      if (needsConsent) {
        await requests.requestConsent({
          kind: method === 'eth_requestAccounts' ? 'connect' : method === 'eth_sendTransaction' ? 'transaction' : 'sign',
          method,
          params,
          dappOrigin: context.dappOrigin,
          // The chain is material to the decision the user is making, so every consent
          // screen names it (MC-80) — by name, not by number (MC-81).
          chainId: runtime.chainId,
          chainName: runtime.chainName,
          runtime,
        });
      }
      try {
        return await runtime.provider.request({ method, params } as never);
      } catch (error) {
        throw toRpcError(error);
      }
    },
  });

  return { transport, requests, getDappOrigin: () => transport.dappOrigin };
}
