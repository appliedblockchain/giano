/**
 * Reading a reason out of whatever was thrown.
 *
 * Wallets are the reason this exists. What a browser wallet rejects with has crossed a process
 * boundary and arrived as a serialised JSON-RPC error — `{ code, message, data }`, a plain object
 * and not an `Error` — so the usual `error instanceof Error ? error.message : String(error)` prints
 * `[object Object]` over the one sentence the operator needed. Some wallets nest the useful half
 * another level down, under `data`, where the node's own words end up.
 */
export function describeError(error: unknown): string {
  if (typeof error === 'string') return error;
  if (error instanceof Error && error.message) return error.message;

  if (error && typeof error === 'object') {
    const { message, data } = error as { message?: unknown; data?: unknown };
    if (typeof message === 'string' && message) return message;

    if (data && typeof data === 'object') {
      const nested = (data as { message?: unknown; originalError?: { message?: unknown } }).message ?? (data as { originalError?: { message?: unknown } }).originalError?.message;
      if (typeof nested === 'string' && nested) return nested;
    }
  }

  return 'no reason given';
}
