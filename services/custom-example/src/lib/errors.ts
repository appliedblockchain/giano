import { TransportRpcError } from '@appliedblockchain/giano-connector';

/** Human-readable error text, distinguishing wallet RPC errors from generic failures. */
export function describeError(error: unknown): string {
  if (error instanceof TransportRpcError) return `rpc:${error.code} ${error.message}`;
  if (error instanceof Error) return error.message;
  return String(error);
}

/** 0x1234…abcd */
export function shortAddress(address?: string | null): string {
  if (!address) return '';
  return `${address.slice(0, 6)}…${address.slice(-4)}`;
}
