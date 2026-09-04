import { RPC_ERRORS, TransportHost, TransportRpcError } from '@appliedblockchain/giano-wallet-transport';
import type { WalletConfig } from './config';
import { createRequestStore, toRpcError, type RequestStore } from './requests';
import type { WalletRuntime, WalletRuntimes } from './runtimes';

const CONSENT_METHODS = new Set(['eth_sendTransaction', 'personal_sign', 'eth_sign', 'eth_signTypedData_v4']);

export type WalletHost = {
  /** Attach transport listeners and announce readiness to the opener. */
  start: () => void;
  stop: () => void;
  /** The single-slot pending-request queue, as subscribable state (WK-10). */
  requests: RequestStore;
  /** The pinned dApp origin, or null before the handshake. */
  readonly dappOrigin: string | null;
};

export type CreateWalletHostOptions = {
  runtimes: WalletRuntimes;
  config: WalletConfig;
  walletVersion: string;
};

type RequestContext = { dappOrigin: string; chainId: number };

/**
 * The transport-facing request handler, factored out of the host so the consent semantics are
 * testable without a live postMessage transport. Not part of the kit's public surface.
 */
export function createHostRequestHandler({
  runtimes,
  requests,
  onChainFirstUsed,
}: {
  runtimes: WalletRuntimes;
  requests: RequestStore;
  onChainFirstUsed?: (runtime: WalletRuntime) => void;
}) {
  // Event relay is wired per runtime, once, when a session first touches that chain.
  const wiredChains = new Set<number>();
  const runtimeForSession = (chainId: number): WalletRuntime => {
    const runtime = runtimes.runtimeFor(chainId);
    if (!wiredChains.has(chainId)) {
      wiredChains.add(chainId);
      onChainFirstUsed?.(runtime);
    }
    return runtime;
  };

  return async (method: string, params: unknown, context: RequestContext): Promise<unknown> => {
    // MC-14/WK-11: chain switching is refused explicitly with EIP-1193 4200 — never silently
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
    // WK-12: a signing/tx request can land on a freshly (re)opened popup whose in-memory
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
  };
}

/**
 * Wires the popup transport to the Giano provider with a consent gate (WK-08):
 * - eth_requestAccounts → a 'connect' request
 * - eth_sendTransaction → a 'transaction' request
 * - personal_sign / eth_sign / eth_signTypedData_v4 → a 'sign' request
 * - giano_openWalletManagement → a 'manage' request (resolves when the view closes)
 * - everything else (read paths) forwards straight to the provider
 * All signing and credential work happens HERE, on the wallet origin — the dApp only
 * ever sees postMessage RPC. The host is headless: it never renders consent, it awaits
 * the decision the UI raises through approve()/reject() (D7, WK-09).
 *
 * The chain is negotiated once per transport session, in the handshake (S1): every request
 * on the session is served by that chain's runtime, resolved lazily on first use (MC-44),
 * and there is no path by which a request reaches a different chain's runtime.
 */
export function createWalletHost({ runtimes, config, walletVersion }: CreateWalletHostOptions): WalletHost {
  const requests = createRequestStore();

  let transport: TransportHost;
  const onRequest = createHostRequestHandler({
    runtimes,
    requests,
    onChainFirstUsed: (runtime) => {
      // relay provider events (accountsChanged, chainChanged, disconnect) to the dApp
      for (const event of ['accountsChanged', 'chainChanged', 'disconnect'] as const) {
        runtime.provider.on(event, (data: unknown) => transport.sendEvent(event, data));
      }
    },
  });

  transport = new TransportHost({
    walletVersion,
    allowedOrigins: config.allowedDappOrigins,
    // The closed list the handshake negotiates against (MC-03): a dApp naming a chain
    // outside it is refused before any request — or passkey ceremony (MC-85) — happens.
    servedChainIds: [...runtimes.servedChainIds],
    onRequest,
  });

  return {
    start: () => transport.start(),
    stop: () => transport.stop(),
    requests,
    get dappOrigin() {
      return transport.dappOrigin;
    },
  };
}
