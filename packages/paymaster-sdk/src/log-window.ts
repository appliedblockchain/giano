import type { PaymasterPublicClient } from './client';

/**
 * One `eth_getLogs`, and the block range it actually covered.
 *
 * Every log read in this SDK is a single query over a window anchored at the chain head, because
 * the alternative does not survive contact with a hosted RPC. Providers cap the span one query may
 * cover — Base and Ethereum Sepolia at 10,000 blocks — so reading a contract's whole history means
 * walking it a window at a time, and that walk grows by about five windows a day on a two-second
 * chain. A reader built that way works for a month and then does not.
 *
 * A window is constant in chain age forever. What it costs is that the answer covers a range rather
 * than all of history, which is why every read here returns the range it covered: a caller can say
 * so on screen, and can page backwards by asking for the window before it.
 */

/**
 * Span to ask for first. Under the 10,000 the common public endpoints allow, because several of
 * them count inclusively and reject a request for exactly their stated limit.
 */
export const DEFAULT_LOG_WINDOW = 9_000n;

/** Narrowing stops here. A node this restrictive cannot usefully serve a log read at all. */
const MIN_LOG_WINDOW = 250n;

/** A block range, inclusive at both ends. */
export type BlockRange = {
  fromBlock: bigint;
  toBlock: bigint;
};

/**
 * The window a read covered, and where to look for the one before it.
 *
 * Every log-backed read returns this alongside its result, so a caller can say on screen which
 * blocks it is showing rather than implying it has everything.
 */
export type Page = BlockRange & {
  /**
   * The window before this one, or `undefined` at the genesis end. Pass it back as `range` to step
   * further into the past — this is the whole of the paging protocol.
   */
  older?: BlockRange;
};

/** A page, alongside the logs found in it. */
export type Windowed<T> = Page & { logs: readonly T[] };

/**
 * True for the rejection a node returns when the requested span exceeds its cap.
 *
 * Matched on the message rather than the code because the codes are not standardised — Base
 * returns -32614, Infura -32005, Alchemy -32602 — and each of those is also used for unrelated
 * failures by someone. The messages all name the range.
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
 * Resolves the range a read should cover: the caller's, or `window` blocks ending at the head.
 *
 * `toBlock` is clamped to the head, so a caller paging forward past the tip reads the tip rather
 * than asking for blocks that do not exist yet. That clamp can leave `fromBlock` above `toBlock`
 * when the caller named a range entirely in the future; the range is returned inverted and
 * {@link readWindow} answers it as empty, which is the truthful answer — no block in it has been
 * mined — rather than an error about arithmetic the caller never did.
 */
export async function resolveWindow(
  publicClient: PaymasterPublicClient,
  range: Partial<BlockRange> | undefined,
  window: bigint,
): Promise<BlockRange> {
  // A non-positive window is a misconfiguration, not a range: it would put `fromBlock` above
  // `toBlock` on the *default* path, where the caller named nothing and so has nothing to debug.
  if (window <= 0n) throw new RangeError(`a log window must span at least one block, got ${window}`);

  const head = await publicClient.getBlockNumber();
  const toBlock = range?.toBlock === undefined || range.toBlock > head ? head : range.toBlock;
  const fromBlock = range?.fromBlock ?? (toBlock >= window ? toBlock - window + 1n : 0n);
  return { fromBlock: fromBlock < 0n ? 0n : fromBlock, toBlock };
}

/**
 * Runs `query` over `range`, narrowing the span and retrying if the node refuses it as too wide.
 *
 * The narrowing is what lets the same code work against a provider with a tighter cap than the
 * default without anyone configuring it: the first refusal halves the request, and `onNarrow` hands
 * the working span back so the caller can keep it for subsequent reads instead of rediscovering it.
 * A narrowed read covers less than was asked for, and the returned range says so rather than
 * letting the caller assume it got what it requested.
 */
export async function readWindow<T>(
  range: BlockRange,
  query: (range: BlockRange) => Promise<readonly T[]>,
  onNarrow?: (window: bigint) => void,
): Promise<Windowed<T>> {
  let { fromBlock } = range;
  const { toBlock } = range;

  // An empty range holds no logs by definition, so answering it costs nothing and sending it to a
  // node would only earn an error about a request this library built.
  if (fromBlock > toBlock) return { fromBlock, toBlock, logs: [] };

  for (;;) {
    try {
      const logs = await query({ fromBlock, toBlock });
      return { fromBlock, toBlock, logs, older: olderThan(fromBlock, toBlock - fromBlock + 1n) };
    } catch (cause) {
      const span = toBlock - fromBlock + 1n;
      if (!isBlockRangeError(cause) || span <= MIN_LOG_WINDOW) throw cause;

      const narrowed = span / 2n < MIN_LOG_WINDOW ? MIN_LOG_WINDOW : span / 2n;
      onNarrow?.(narrowed);
      fromBlock = toBlock - narrowed + 1n;
    }
  }
}

/** The window of the same width immediately below `fromBlock`, or nothing at genesis. */
function olderThan(fromBlock: bigint, width: bigint): BlockRange | undefined {
  if (fromBlock === 0n) return undefined;
  const toBlock = fromBlock - 1n;
  return { fromBlock: toBlock >= width ? toBlock - width + 1n : 0n, toBlock };
}
