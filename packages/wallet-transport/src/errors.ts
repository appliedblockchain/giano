import type { HandshakeNackReason, RpcError } from './protocol';
import { RPC_ERRORS } from './protocol';

export type TransportErrorCode =
  | 'POPUP_BLOCKED'
  | 'POPUP_CLOSED'
  | 'HANDSHAKE_TIMEOUT'
  | 'HANDSHAKE_REFUSED'
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

/**
 * The wallet origin refused the handshake (`handshake:nack`) — distinguishable from every
 * other connection failure, with a machine-readable reason (MC-04). For chain refusals the
 * served chains are carried along, so an integrator can diagnose the mismatch without
 * access to the wallet origin's configuration.
 */
export class HandshakeRefusedError extends TransportError {
  constructor(
    public readonly reason: HandshakeNackReason,
    message: string,
    public readonly supportedChainIds: readonly number[] = [],
  ) {
    super('HANDSHAKE_REFUSED', message);
    this.name = 'HandshakeRefusedError';
  }
}

/**
 * The wallet origin does not serve the requested chain (permanent — unlike 4901, which is
 * a temporarily unreachable chain and worth retrying, MC-55). Code 4902 is EIP-3326's
 * "Unrecognized chain ID", the ecosystem convention. Extends {@link TransportRpcError}
 * because the code is an EIP-1193 numeric, not a transport-channel failure.
 */
export class UnsupportedChainError extends TransportRpcError {
  public readonly reason: HandshakeNackReason;
  constructor(
    public readonly requestedChainId: number | undefined,
    public readonly supportedChainIds: readonly number[],
    message?: string,
  ) {
    super(
      RPC_ERRORS.UNSUPPORTED_CHAIN,
      message ??
        (requestedChainId === undefined
          ? `the connection named no chain — this wallet serves: ${supportedChainIds.join(', ')}`
          : `this wallet does not serve chain ${requestedChainId} — it serves: ${supportedChainIds.join(', ')}`),
      { supportedChainIds },
    );
    this.reason = requestedChainId === undefined ? 'chain-required' : 'unsupported-chain';
    this.name = 'UnsupportedChainError';
  }
}
