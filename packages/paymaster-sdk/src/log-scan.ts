import { LogRangeUnboundedError } from './errors';

/**
 * Windowed log queries.
 *
 * `eth_getLogs` over `earliest`..`latest` is only servable by a node willing to scan the whole
 * chain for you. Hosted RPCs refuse it instead, capping the span a single query may cover — Base
 * and Ethereum Sepolia at 10,000 blocks, others lower — so a client that wants the full history
 * has to ask for it a window at a time and stitch the answers together.
 *
 * Two things follow, and both are why this is a module rather than a loop inlined at each call
 * site:
 *
 * - The cap belongs to the node, not the chain, and is not discoverable up front. The scan starts
 *   at a width most providers accept and *narrows on rejection*, keeping the narrowed width for
 *   the rest of the scan. An operator does not have to know their provider's limit to get a
 *   correct answer out of it.
 * - A window count is a request count. Scanning a 47-million-block chain from genesis at 9,000
 *   blocks a window is five thousand round trips — not a slow query but a broken one. So the scan
 *   refuses an unbounded range up front and names what to configure instead of grinding.
 */

/**
 * Starting window width. Below the 10,000 the common public endpoints allow, because several of
 * them count the span inclusively and reject a request for exactly their stated limit.
 */
export const DEFAULT_MAX_BLOCK_RANGE = 9_000n;

/** Narrowing stops here. A node this restrictive cannot serve a history scan at any width. */
const MIN_BLOCK_RANGE = 250n;

/**
 * Windows one scan may span before it is refused as unbounded. 2,000 at the default width is 18
 * million blocks — more than any real deployment's history, and less than a chain's.
 */
const MAX_WINDOWS = 2_000n;

/** Windows in flight at once. Quick enough to keep a console responsive, gentle enough on rate limits. */
const CONCURRENCY = 4;

export type LogScan<T> = {
  fromBlock: bigint;
  toBlock: bigint;
  /** Width to try first. Narrowed automatically when the node rejects it. */
  maxRange?: bigint;
  /** Named in {@link LogRangeUnboundedError} when the range is too wide to scan. */
  subject: string;
  query: (fromBlock: bigint, toBlock: bigint) => Promise<readonly T[]>;
};

/**
 * True for the rejection a node returns when the requested span exceeds its cap.
 *
 * Matched on the message rather than the code because the codes are not standardised — Base
 * returns -32614, Infura -32005, Alchemy -32602 — and every one of those is also used for
 * unrelated failures by someone. The messages all name the range.
 */
export function isBlockRangeError(error: unknown): boolean {
  const message = flatten(error).toLowerCase();
  if (!message) return false;
  return (
    /limited to a[^.]*range/.test(message) ||
    /block range/.test(message) ||
    /range is too large|range too large|too wide|too many blocks|exceeds? the maximum|max(imum)? (block )?range/.test(message) ||
    /query returned more than|response size exceeded|log response size/.test(message)
  );
}

/** Every message in the error's cause chain, so a viem-wrapped RPC error still matches. */
function flatten(error: unknown): string {
  if (typeof error === 'string') return error;
  const parts: string[] = [];
  const seen = new Set<unknown>();
  let current: unknown = error;
  while (current && typeof current === 'object' && !seen.has(current)) {
    seen.add(current);
    const record = current as { message?: unknown; details?: unknown; shortMessage?: unknown; cause?: unknown };
    for (const field of [record.shortMessage, record.details, record.message]) {
      if (typeof field === 'string') parts.push(field);
    }
    current = record.cause;
  }
  return parts.join(' ');
}

/**
 * Runs `query` over `[fromBlock, toBlock]` in windows, concatenated in block order.
 *
 * Windows are claimed from a shared cursor rather than sliced up front, so a width narrowed by one
 * rejection applies to every window still unclaimed — one node-limit discovery per scan instead of
 * one per window. Results are reassembled by start block, so the concatenation is chain order and
 * callers documenting "newest last" stay correct without re-sorting.
 */
export async function scanLogs<T>(scan: LogScan<T>): Promise<T[]> {
  const { fromBlock, toBlock, subject, query } = scan;
  if (toBlock < fromBlock) return [];

  let width = clamp(scan.maxRange ?? DEFAULT_MAX_BLOCK_RANGE);
  if ((toBlock - fromBlock + 1n) / width > MAX_WINDOWS) {
    throw new LogRangeUnboundedError(subject, fromBlock, toBlock, width);
  }

  const chunks: Array<{ from: bigint; logs: readonly T[] }> = [];
  let cursor = fromBlock;

  const scanWindow = async (from: bigint, to: bigint): Promise<void> => {
    try {
      chunks.push({ from, logs: await query(from, to) });
    } catch (cause) {
      const span = to - from + 1n;
      if (!isBlockRangeError(cause) || span <= MIN_BLOCK_RANGE) throw cause;

      const half = clamp(span / 2n);
      if (half < width) width = half;

      // Re-split at the *current* width rather than at half the failed span, and re-read it each
      // time round: a further narrowing inside one of these applies to the rest of them, so the
      // cap is found by halving once and not once per sibling.
      for (let start = from; start <= to; ) {
        const end = start + width - 1n > to ? to : start + width - 1n;
        await scanWindow(start, end);
        start = end + 1n;
      }
    }
  };

  const claim = (): { from: bigint; to: bigint } => {
    // Read and advance together: the runtime is single-threaded, so no other worker can claim this
    // window between the two statements.
    const from = cursor;
    const to = from + width - 1n > toBlock ? toBlock : from + width - 1n;
    cursor = to + 1n;
    return { from, to };
  };

  // The first window runs alone. Discovering the node's real width costs a rejection per halving,
  // and four workers starting at once would each pay for that discovery separately.
  const first = claim();
  await scanWindow(first.from, first.to);

  await Promise.all(
    Array.from({ length: CONCURRENCY }, async () => {
      while (cursor <= toBlock) {
        const { from, to } = claim();
        await scanWindow(from, to);
      }
    }),
  );

  return chunks
    .sort((a, b) => (a.from < b.from ? -1 : a.from > b.from ? 1 : 0))
    .flatMap((chunk) => [...chunk.logs]);
}

function clamp(width: bigint): bigint {
  return width < MIN_BLOCK_RANGE ? MIN_BLOCK_RANGE : width;
}
