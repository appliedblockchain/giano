import type { RpcError } from './protocol';

export type TransportErrorCode =
  | 'POPUP_BLOCKED'
  | 'POPUP_CLOSED'
  | 'HANDSHAKE_TIMEOUT'
  | 'REQUEST_TIMEOUT'
  | 'DISCONNECTED'
  | 'NOT_CONNECTED';

/**
 * Transport-layer failure (popup/channel), as opposed to an in-band RPC error.
 *
 * `POPUP_BLOCKED` also fires when a dApp serves `Cross-Origin-Opener-Policy: same-origin`,
 * which severs `window.opener` — the wallet's `ready` never arrives. dApps must use
 * `same-origin-allow-popups` (or no COOP header).
 */
export class TransportError extends Error {
  constructor(
    public readonly code: TransportErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'TransportError';
  }
}

/** In-band EIP-1193 RPC error relayed from the wallet (e.g. 4001 user rejected). */
export class TransportRpcError extends Error {
  constructor(
    public readonly code: number,
    message: string,
    public readonly data?: unknown,
  ) {
    super(message);
    this.name = 'TransportRpcError';
  }

  static from(error: RpcError): TransportRpcError {
    return new TransportRpcError(error.code, error.message, error.data);
  }
}
