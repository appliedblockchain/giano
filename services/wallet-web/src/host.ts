import { TransportHost } from '@appliedblockchain/giano-wallet-transport';
import type { WalletConfig } from './config';
import { createRequestStore, toRpcError, type RequestStore } from './requests';
import type { WalletRuntime } from './wallet';

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
 */
export function createWalletHost(runtime: WalletRuntime, config: WalletConfig, walletVersion: string): WalletHost {
  const requests = createRequestStore();

  const transport = new TransportHost({
    walletVersion,
    allowedOrigins: config.allowedDappOrigins,
    onRequest: async (method, params, context) => {
      const needsConsent = method === 'eth_requestAccounts' || CONSENT_METHODS.has(method);
      if (needsConsent) {
        await requests.requestConsent({
          kind: method === 'eth_requestAccounts' ? 'connect' : method === 'eth_sendTransaction' ? 'transaction' : 'sign',
          method,
          params,
          dappOrigin: context.dappOrigin,
        });
      }
      try {
        return await runtime.provider.request({ method, params } as never);
      } catch (error) {
        throw toRpcError(error);
      }
    },
  });

  // relay provider events (accountsChanged, chainChanged, disconnect) to the dApp
  for (const event of ['accountsChanged', 'chainChanged', 'disconnect'] as const) {
    runtime.provider.on(event, (data: unknown) => transport.sendEvent(event, data));
  }

  return { transport, requests, getDappOrigin: () => transport.dappOrigin };
}
