import { TransportRpcError, RPC_ERRORS } from '@appliedblockchain/giano-wallet-transport';
import type { WalletRuntime } from './wallet';

/** A dApp request awaiting user consent in the popup UI. */
export type PendingRequest = {
  /** 'manage' opens the wallet-management view (WM-54); it resolves when the user closes it. */
  kind: 'connect' | 'transaction' | 'sign' | 'manage';
  method: string;
  params: unknown;
  dappOrigin: string;
  /** The chain this session negotiated — named on every consent screen (MC-80, MC-81). */
  chainId: number;
  chainName: string;
  /** The per-chain runtime serving this session (sponsorship pre-flight and all). */
  runtime: WalletRuntime;
  approve: () => void;
  reject: () => void;
};

type Listener = (pending: PendingRequest | null) => void;

/**
 * Single-slot consent queue: the popup shows one request at a time; approval runs the
 * request through the Giano provider, rejection answers 4001 without touching it.
 */
export function createRequestStore() {
  let current: PendingRequest | null = null;
  const listeners = new Set<Listener>();

  const notify = () => listeners.forEach((listener) => listener(current));

  return {
    get current() {
      return current;
    },
    subscribe(listener: Listener): () => void {
      listeners.add(listener);
      listener(current);
      return () => listeners.delete(listener);
    },
    /** Resolves with the user's decision; the caller performs the actual request. */
    requestConsent(input: Omit<PendingRequest, 'approve' | 'reject'>): Promise<void> {
      if (current) {
        return Promise.reject(new TransportRpcError(RPC_ERRORS.INTERNAL, 'another request is already pending'));
      }
      return new Promise<void>((resolve, reject) => {
        current = {
          ...input,
          approve: () => {
            current = null;
            notify();
            resolve();
          },
          reject: () => {
            current = null;
            notify();
            reject(new TransportRpcError(RPC_ERRORS.USER_REJECTED, 'User rejected the request'));
          },
        };
        notify();
      });
    },
  };
}

export type RequestStore = ReturnType<typeof createRequestStore>;

/** Maps WebAuthn/user-abort failures to 4001; everything else to an internal RPC error. */
export function toRpcError(error: unknown): TransportRpcError {
  if (error instanceof TransportRpcError) return error;
  const name = (error as { name?: string })?.name;
  const message = error instanceof Error ? error.message : 'request failed';
  if (name === 'NotAllowedError' || name === 'AbortError') {
    return new TransportRpcError(RPC_ERRORS.USER_REJECTED, 'User cancelled the passkey ceremony');
  }
  // The account couldn't be (re)established — the popup was reopened and the persisted
  // session is gone/expired. Surface a clean EIP-1193 disconnect so the dApp reconnects.
  if (/not connected/i.test(message)) {
    return new TransportRpcError(RPC_ERRORS.DISCONNECTED, 'Wallet session expired — reconnect');
  }
  return new TransportRpcError(RPC_ERRORS.INTERNAL, message);
}
