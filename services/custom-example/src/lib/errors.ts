import { HandshakeRefusedError, RPC_ERRORS, TransportError, TransportRpcError, UnsupportedChainError, UnsupportedChainSwitchError } from '@appliedblockchain/giano-connector';

/**
 * A typed error record for the ledger (demo-dapp spec, "Failure paths are controls"): class name,
 * code, message and data, plus the fields the connector's own error classes carry. Nothing is
 * collapsed into a string — a bug report needs all of it.
 */
export type ErrorRecord = {
  name: string;
  code?: number | string;
  message: string;
  data?: unknown;
  /** HandshakeRefusedError / UnsupportedChainError reason (origin-not-allowed, unsupported-chain, chain-required). */
  reason?: string;
  requestedChainId?: number;
  supportedChainIds?: readonly number[];
  /** Plain-language reading of the error, written for the person reproducing it. */
  meaning?: string;
  /** What the operator or integrator does about it, when the demo knows. */
  action?: string;
};

export const RPC_CODE_LABEL: Record<number, string> = {
  4001: 'user rejected (or the wallet refused before approval)',
  4100: 'unauthorized',
  4200: 'unsupported method',
  4900: 'disconnected',
  4901: 'chain served but unreachable',
  4902: 'chain not served by this wallet',
};

export function describeError(error: unknown, context?: { sponsoredSend?: boolean }): ErrorRecord {
  if (error instanceof UnsupportedChainError) {
    return {
      name: 'UnsupportedChainError',
      code: error.code,
      message: error.message,
      data: error.data,
      reason: error.reason,
      requestedChainId: error.requestedChainId,
      supportedChainIds: error.supportedChainIds,
      meaning: 'The wallet origin does not serve this chain. Permanent until the operator adds it.',
      action: `Ask the wallet operator to serve chain ${error.requestedChainId ?? '?'}, or pick one of ${error.supportedChainIds.join(', ') || 'the served chains'}.`,
    };
  }
  if (error instanceof HandshakeRefusedError) {
    const originNotAllowed = error.reason === 'origin-not-allowed';
    return {
      name: 'HandshakeRefusedError',
      code: error.code,
      message: error.message,
      reason: error.reason,
      supportedChainIds: error.supportedChainIds,
      meaning: originNotAllowed
        ? 'The wallet origin refused the handshake because this dApp origin is not allow-listed. The served-chains list is deliberately withheld from a disallowed origin.'
        : 'The wallet origin refused the handshake.',
      action: originNotAllowed ? `Add ${window.location.origin} to the tenant's allowedDappOrigins and corsOrigins, then restart wallet-api / wallet-web.` : undefined,
    };
  }
  if (error instanceof UnsupportedChainSwitchError) {
    return {
      name: 'UnsupportedChainSwitchError',
      message: error.message,
      requestedChainId: error.requestedChainId,
      meaning: 'Expected. wagmi asked the connector to switch chains; Giano binds one chain per provider.',
    };
  }
  if (error instanceof TransportRpcError) {
    const record: ErrorRecord = { name: 'TransportRpcError', code: error.code, message: error.message, data: error.data };
    const label = RPC_CODE_LABEL[error.code];
    if (label) record.meaning = label;
    if (error.code === RPC_ERRORS.USER_REJECTED) {
      record.meaning = context?.sponsoredSend
        ? 'Closed by the user, OR refused in the wallet before approval (sponsorship not configured, contract not allow-listed, tenant out of funds). The application receives the same 4001 either way — see finding G5.'
        : 'The user dismissed the request in the wallet.';
      record.action = context?.sponsoredSend ? 'Open the wallet popup console: the refusal reason is logged there as [giano] sponsorship refused.' : undefined;
    }
    if (error.code === RPC_ERRORS.UNSUPPORTED_METHOD) {
      record.meaning = 'Expected. Giano binds one chain per provider instance; a switch or add is refused with 4200.';
    }
    if (error.code === 4900) {
      record.meaning = 'The wallet no longer recognises this session. The connector dropped its cache; reconnect with eth_requestAccounts.';
    }
    if (error.code === 4901) {
      record.meaning = 'The wallet serves this chain but cannot reach its node right now. Worth retrying.';
    }
    if (/AA21/.test(error.message)) {
      record.meaning = 'AA21: the account did not prefund the EntryPoint. Self-paid operation with no native balance on this chain.';
      record.action = 'Fund the account on this chain, or declare the operation sponsored on a chain where the tenant sponsors.';
    }
    return record;
  }
  if (error instanceof TransportError) {
    const record: ErrorRecord = { name: 'TransportError', code: error.code, message: error.message };
    if (error.code === 'POPUP_BLOCKED') {
      record.meaning = 'The browser blocked the wallet popup.';
      record.action = 'Call wallet methods from a user gesture, and do not serve this page with Cross-Origin-Opener-Policy: same-origin.';
    }
    if (error.code === 'HANDSHAKE_TIMEOUT') {
      record.meaning = 'The popup opened but the wallet never answered.';
      record.action = 'Check the wallet URL, the COOP header of this page, and that the wallet origin is up. See the preflight card.';
    }
    if (error.code === 'REQUEST_TIMEOUT') {
      record.meaning = 'No answer within the connector deadline. For a receipt, the operation may still land — keep waiting by hash.';
    }
    return record;
  }
  if (error instanceof Error) {
    return { name: error.name || 'Error', message: error.message, data: (error as { data?: unknown }).data, code: (error as { code?: number | string }).code };
  }
  return { name: 'Unknown', message: String(error) };
}

export function isSessionEnded(error: unknown): boolean {
  return (error instanceof TransportRpcError && error.code === RPC_ERRORS.DISCONNECTED) || (error instanceof TransportError && error.code === 'DISCONNECTED');
}
