/**
 * ERC-1967 proxies (the paymaster proxy): which implementation a proxy delegates to. One reader for
 * the deploy tooling, giano-doctor and wallet-api, whatever client they use.
 */
import {
	type Address,
	getAddress,
	type Hex,
	isAddress,
	type PublicClient,
} from "viem";

/** bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1). */
export const IMPLEMENTATION_SLOT =
	"0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

/** keccak256("Upgraded(address)"): the event ERC-1967 emits each time the implementation changes. */
export const UPGRADED_TOPIC: Hex =
	"0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b";

/**
 * The block span of one `eth_getLogs` request when the slot cannot be read, counted inclusively.
 * 9,000, not 10,000: several public RPCs count inclusively and refuse exactly 10,000, and wallet-api's
 * platform read relay may be configured down to 9,000 (`PLATFORM_RPC_MAX_LOG_BLOCKS`). The same value
 * as the paymaster SDK's `DEFAULT_LOG_WINDOW`. The SDK depends on this package, so this package
 * cannot import it. Keep the two equal.
 */
export const UPGRADED_LOG_CHUNK = 9_000n;

/**
 * The default number of `eth_getLogs` requests one walk sends before it gives up: 9,000,000 blocks.
 * Below the platform read relay's default of 1,200 requests a minute, so one walk fits its budget.
 */
export const UPGRADED_LOG_MAX_CHUNKS = 1_000;

/**
 * The block that deployed the proxy at `proxy`, taken from `deployed` only when `deployed` records
 * that same proxy: where a walk through its `Upgraded` logs can start. A block recorded for another
 * proxy would start the walk past this proxy's upgrades, so it is never used. Undefined when the
 * addresses differ, or either is missing, or `deployed` has no block: the walk then starts at block 0.
 * Addresses compare without regard to case. A malformed one never matches, not even an identical
 * malformed one: giano-doctor passes its flags through unvalidated. giano-doctor, wallet-api and the
 * deploy tooling all decide the walk's start here.
 */
export function proxyDeployBlock(
	proxy: Address | undefined,
	deployed: { address?: Address; blockNumber?: number | bigint } | undefined,
): bigint | undefined {
	if (
		proxy === undefined ||
		deployed?.address === undefined ||
		deployed.blockNumber === undefined
	)
		return undefined;
	// Two identical malformed values must not match either: check both are 20 hex bytes first.
	if (
		!isAddress(proxy, { strict: false }) ||
		!isAddress(deployed.address, { strict: false })
	)
		return undefined;
	return proxy.toLowerCase() === deployed.address.toLowerCase()
		? BigInt(deployed.blockNumber)
		: undefined;
}

/** Bounds on the backwards walk through a proxy's `Upgraded` logs. */
export type UpgradedLogWalkOptions = {
	/** The lowest block to search, such as the proxy's deployment block. Default 0. */
	fromBlock?: bigint;
	/**
	 * The most `eth_getLogs` requests one read sends, a non-negative safe integer. Default
	 * {@link UPGRADED_LOG_MAX_CHUNKS}.
	 */
	maxChunks?: number;
};

/**
 * The depth, in blocks, below which a reorganisation is not expected. The per-client memory keeps
 * only what it found this far behind the head, and every read searches the newer blocks again.
 */
const UPGRADED_LOG_CONFIRMATIONS = 64n;

/**
 * The walk sent `maxChunks` requests, did not reach `fromBlock`, and found no `Upgraded` event.
 * Every request was answered: the search is incomplete, the RPC is not unreachable.
 * {@link proxyImplementationWithSource} throws this type too, with the proxy in the message.
 */
export class UpgradedLogWalkLimitError extends Error {
	constructor(message: string, options?: ErrorOptions) {
		super(message, options);
		this.name = "UpgradedLogWalkLimitError";
	}
}

/** The message of an {@link UpgradedLogWalkLimitError}. */
function walkLimitMessage(
	fromBlock: bigint,
	toBlock: bigint,
	maxChunks: number,
	recovery: string,
): string {
	return `no Upgraded event in blocks ${fromBlock}-${toBlock}, and the walk stops after ${maxChunks} eth_getLogs requests. ${recovery}`;
}

/**
 * True when `error`, or an error in its `cause` chain, is an {@link UpgradedLogWalkLimitError}.
 * Compares the name, so it also holds across two copies of this package.
 */
export function isUpgradedLogWalkLimitError(error: unknown): boolean {
	for (
		let current: unknown = error, depth = 0;
		current instanceof Error && depth < 5;
		current = current.cause, depth++
	)
		if (current.name === "UpgradedLogWalkLimitError") return true;
	return false;
}

/** Refuses a `maxChunks` that would not bound the walk: only a non-negative safe integer does. */
function checkMaxChunks(maxChunks: number): void {
	if (!Number.isSafeInteger(maxChunks) || maxChunks < 0)
		throw new RangeError(
			`maxChunks must be a non-negative integer, not ${maxChunks}`,
		);
}

/**
 * Walks back from `to` to `floor` in chunks of {@link UPGRADED_LOG_CHUNK} blocks, newest first, and
 * stops at the first chunk that holds a log, or after `maxChunks` requests. Returns that chunk's
 * logs (none when it found none), the lowest block searched, and the number of requests sent. A
 * `low` above `floor` with no logs means the walk stopped at the limit. When a request fails, it
 * stops there and returns the error as `failure`, with `low` the lowest block of the chunks that
 * were answered, so the caller can keep that progress.
 */
async function walkBack<Log>(
	getLogs: (fromBlock: bigint, toBlock: bigint) => Promise<readonly Log[]>,
	to: bigint,
	floor: bigint,
	maxChunks: number,
): Promise<{
	logs: readonly Log[];
	low: bigint;
	requests: number;
	failure?: { error: unknown };
}> {
	let low = to + 1n;
	let requests = 0;
	while (low > floor && requests < maxChunks) {
		const high = low - 1n;
		const next =
			high - floor >= UPGRADED_LOG_CHUNK - 1n
				? high - UPGRADED_LOG_CHUNK + 1n
				: floor;
		requests++;
		let logs: readonly Log[];
		try {
			logs = await getLogs(next, high);
		} catch (error) {
			return { logs: [], low, requests, failure: { error } };
		}
		low = next;
		if (logs.length > 0) return { logs, low, requests };
	}
	return { logs: [], low, requests };
}

/**
 * The implementation address a raw implementation-slot word holds (the low 20 bytes), or null when
 * the slot is empty or zero. Takes the word as any client returns it: 32 bytes, shorter, or "0x".
 */
export function implementationFromSlot(
	word: string | null | undefined,
): Address | null {
	if (!word || !/^0x[0-9a-fA-F]*$/.test(word)) return null;
	const low = word.slice(2).padStart(40, "0").slice(-40);
	return /^0+$/.test(low) ? null : getAddress(`0x${low}`);
}

/**
 * The implementation named by the proxy's latest `Upgraded` event, or null when it emitted none
 * between `fromBlock` and `latest`. For an RPC that refuses `eth_getStorageAt` (Silent Data): walks
 * back from `latest` in chunks of {@link UPGRADED_LOG_CHUNK} blocks and stops at the first chunk that
 * holds an upgrade. After `maxChunks` requests without one, it throws instead of walking further.
 * `maxChunks` must be a non-negative safe integer. `getLogs` returns the topics of the proxy's `Upgraded` logs in [fromBlock, toBlock], oldest first.
 */
export async function implementationFromUpgradedLogs(
	getLogs: (
		fromBlock: bigint,
		toBlock: bigint,
	) => Promise<readonly { topics: readonly (string | null)[] }[]>,
	latest: bigint,
	{
		fromBlock = 0n,
		maxChunks = UPGRADED_LOG_MAX_CHUNKS,
	}: UpgradedLogWalkOptions = {},
): Promise<Address | null> {
	checkMaxChunks(maxChunks);
	const { logs, low, failure } = await walkBack(
		getLogs,
		latest,
		fromBlock,
		maxChunks,
	);
	if (failure) throw failure.error;
	const last = logs.at(-1);
	if (last) return implementationFromSlot(last.topics[1]);
	if (low > fromBlock)
		throw new UpgradedLogWalkLimitError(
			walkLimitMessage(
				low,
				latest,
				maxChunks,
				"Pass a larger maxChunks to search further back",
			),
		);
	return null;
}

/**
 * JSON-RPC codes that say the node refused the method itself: -32601 method not found (also
 * wallet-api's read relay, for a method outside its allowlist), -32004 method not supported
 * (EIP-1474), 4200 unsupported method (EIP-1193).
 */
const METHOD_REFUSED_CODES = new Set([-32601, -32004, 4200]);

/**
 * A refusal message that names the method: "JSON RPC method not whitelisted" (the Silent Data
 * gateway), "method eth_getStorageAt is not allowed", "the method eth_x does not exist/is not
 * available" (geth), "Unauthorized method: eth_x". A request body inside a client's error message
 * holds `"method":"eth_x"`, which this does not match.
 */
const METHOD_REFUSED_MESSAGE =
	/\bmethod (?:\S+ )?(?:is )?(?:not whitelisted|not allowed|not supported|not found|does not exist|disabled|blocked|restricted)|\b(?:unsupported|unauthorized|disallowed|forbidden|restricted|blocked) method\b/i;

/**
 * True when the error says the RPC refused the method, as a gateway that blocks `eth_getStorageAt`
 * does. False for a timeout, a rate limit or any other failure: a fallback would only hide those.
 * Follows viem's `cause` chain, and ethers' `error` and `info.error`.
 */
export function isMethodRefusedError(error: unknown): boolean {
	const seen = new Set<unknown>();
	const pending: unknown[] = [error];
	while (pending.length > 0) {
		const current = pending.pop();
		if (typeof current === "string") {
			if (METHOD_REFUSED_MESSAGE.test(current)) return true;
			continue;
		}
		if (!current || typeof current !== "object" || seen.has(current)) continue;
		seen.add(current);
		const record = current as Record<string, unknown>;
		if (
			typeof record.code === "number" &&
			METHOD_REFUSED_CODES.has(record.code)
		)
			return true;
		const info = record.info;
		pending.push(
			record.shortMessage,
			record.details,
			record.message,
			record.cause,
			record.error,
			info && typeof info === "object"
				? (info as { error?: unknown }).error
				: undefined,
		);
	}
	return false;
}

/** One `Upgraded` log as `eth_getLogs` returns it. */
type UpgradedLog = {
	topics: readonly (string | null)[];
	blockNumber?: string | null;
};

/**
 * What the log walks for one proxy and `fromBlock` found, through one client. Every block from `low`
 * to `checkpoint` was searched. The checkpoint stays {@link UPGRADED_LOG_CONFIRMATIONS} blocks
 * behind the head, so a reorganisation does not reach what is kept.
 */
type Walk = {
	checkpoint: bigint;
	/** The newest upgrade at or below the checkpoint; null when none was found down to `low`. */
	implementation: Address | null;
	/** Where the search back stopped: `fromBlock` once it is complete, higher when it hit the limit. */
	low: bigint;
};

/** The memory for one proxy and `fromBlock`, and the read in progress, which concurrent reads share. */
type WalkEntry = { walk?: Walk; reading?: Promise<Address | null> };

/**
 * Per client, then per proxy and `fromBlock`: what the log walks found. A later read searches only
 * the blocks after the checkpoint, so a caller that reads on every block (the console's health
 * check) normally sends one `eth_getLogs`, not the whole walk again. Keyed by the client object, so
 * it lives as long as the client does.
 */
const walks = new WeakMap<object, Map<string, WalkEntry>>();

/** This client's memory for one proxy and `fromBlock`. */
function walkEntry(client: object, key: string): WalkEntry {
	let byKey = walks.get(client);
	if (!byKey) {
		byKey = new Map();
		walks.set(client, byKey);
	}
	let entry = byKey.get(key);
	if (!entry) {
		entry = {};
		byKey.set(key, entry);
	}
	return entry;
}

/**
 * The read in progress for `entry`, or a new one from `start`. One read at a time per entry: a
 * concurrent read shares the one in progress, and each read starts from what the previous one
 * kept, so an older read never overwrites a newer checkpoint.
 */
function sharedRead(
	entry: WalkEntry,
	start: () => Promise<Address | null>,
): Promise<Address | null> {
	if (entry.reading) return entry.reading;
	const reading = start();
	entry.reading = reading;
	const done = () => {
		if (entry.reading === reading) entry.reading = undefined;
	};
	reading.then(done, done);
	return reading;
}

/**
 * The implementation the ERC-1967 proxy at `proxy` delegates to, or null when its slot is empty,
 * and where the answer came from. Reads the slot (`source: "slot"`). When the RPC refuses that
 * method and the client can read logs, it falls back to the latest `Upgraded` event, bounded by
 * `options` (`source: "logs"`). Any other storage-read error is raised unchanged. When the fallback
 * fails too, the error names both failures, with the storage-read error as `cause`.
 *
 * A `"logs"` answer is not verified against the slot: code the proxy delegates to, such as an
 * implementation an upgrade installs, can emit an `Upgraded` event that names another address.
 * When the walk hits `maxChunks`, it throws an {@link UpgradedLogWalkLimitError}, and the next read
 * through the same client continues the search further back. When an `eth_getLogs` request fails,
 * the read throws, and the next read through the same client continues from the blocks that were
 * answered. Pass the proxy's deployment block as `fromBlock` to keep the walk short.
 */
export async function proxyImplementationWithSource(
	client: Pick<PublicClient, "getStorageAt"> &
		Partial<Pick<PublicClient, "getBlockNumber" | "request">>,
	proxy: Address,
	options: UpgradedLogWalkOptions = {},
): Promise<{ implementation: Address | null; source: "slot" | "logs" }> {
	const { fromBlock = 0n, maxChunks = UPGRADED_LOG_MAX_CHUNKS } = options;
	checkMaxChunks(maxChunks);
	try {
		return {
			implementation: implementationFromSlot(
				await client.getStorageAt({
					address: proxy,
					slot: IMPLEMENTATION_SLOT,
				}),
			),
			source: "slot",
		};
	} catch (storageError) {
		const { getBlockNumber, request } = client;
		if (!getBlockNumber || !request || !isMethodRefusedError(storageError))
			throw storageError;
		try {
			const entry = walkEntry(client, `${getAddress(proxy)}:${fromBlock}`);
			const implementation = await sharedRead(entry, async () =>
				implementationSinceCheckpoint(
					entry,
					// viem caches the block number; an upgrade in the newest block must not be missed.
					await getBlockNumber({ cacheTime: 0 }),
					fromBlock,
					maxChunks,
					(from, to) =>
						request({
							method: "eth_getLogs",
							params: [
								{
									address: proxy,
									topics: [UPGRADED_TOPIC],
									fromBlock: `0x${from.toString(16)}`,
									toBlock: `0x${to.toString(16)}`,
								},
							],
						}) as Promise<readonly UpgradedLog[]>,
				),
			);
			return { implementation, source: "logs" };
		} catch (logError) {
			const message = `could not read the implementation of ${proxy}: the RPC refused eth_getStorageAt, and reading its Upgraded logs failed: ${logError instanceof Error ? logError.message : String(logError)}`;
			// A walk that stopped at its limit keeps its type, so a caller can tell an incomplete
			// search from a failed request (isUpgradedLogWalkLimitError).
			throw isUpgradedLogWalkLimitError(logError)
				? new UpgradedLogWalkLimitError(message, { cause: storageError })
				: new Error(message, { cause: storageError });
		}
	}
}

/**
 * The implementation the ERC-1967 proxy at `proxy` delegates to, or null when its slot is empty.
 * {@link proxyImplementationWithSource} without the source: the slot, or, when the RPC refuses
 * `eth_getStorageAt`, the latest `Upgraded` event.
 */
export async function proxyImplementation(
	client: Pick<PublicClient, "getStorageAt"> &
		Partial<Pick<PublicClient, "getBlockNumber" | "request">>,
	proxy: Address,
	options: UpgradedLogWalkOptions = {},
): Promise<Address | null> {
	return (await proxyImplementationWithSource(client, proxy, options))
		.implementation;
}

/**
 * One log read through the memory in `entry`. It searches the blocks after the checkpoint, newest
 * first, and keeps only what lies at or below the new checkpoint. When no upgrade is there and the
 * search back is not complete, it continues from where the last read stopped. It sends at most
 * `maxChunks` requests.
 */
async function implementationSinceCheckpoint(
	entry: WalkEntry,
	latest: bigint,
	fromBlock: bigint,
	maxChunks: number,
	getLogs: (
		fromBlock: bigint,
		toBlock: bigint,
	) => Promise<readonly UpgradedLog[]>,
): Promise<Address | null> {
	// A head below the checkpoint: a reorganisation deeper than the confirmation depth, or a node far
	// behind. Nothing kept is trusted; the walk starts again.
	const walk =
		entry.walk && latest >= entry.walk.checkpoint ? entry.walk : undefined;
	const previous = walk ? walk.checkpoint : fromBlock - 1n;
	// The checkpoint never moves back while the head stays at or above it.
	let checkpoint = latest - UPGRADED_LOG_CONFIRMATIONS;
	if (checkpoint < previous) checkpoint = previous;
	const floor = previous + 1n;

	const recent = await walkBack(getLogs, latest, floor, maxChunks);
	if (recent.failure) {
		// A request failed. A kept answer still holds: nothing below its checkpoint changed. Without
		// one, keep the blocks that were answered, so the next read continues below them.
		if (!walk)
			entry.walk = {
				checkpoint,
				implementation: null,
				low: recent.low > checkpoint ? checkpoint + 1n : recent.low,
			};
		throw recent.failure.error;
	}
	let kept: UpgradedLog | undefined;
	for (const log of recent.logs)
		if (log.blockNumber != null && BigInt(log.blockNumber) <= checkpoint)
			kept = log;
	if (kept)
		entry.walk = {
			checkpoint,
			implementation: implementationFromSlot(kept.topics[1]),
			low: fromBlock,
		};
	else if (recent.low <= floor)
		entry.walk = walk
			? { ...walk, checkpoint }
			: { checkpoint, implementation: null, low: fromBlock };
	// The search stopped above the old checkpoint: what lies between is unknown, so the search goes
	// on back from here.
	else
		entry.walk = {
			checkpoint,
			implementation: null,
			low: recent.low > checkpoint ? checkpoint + 1n : recent.low,
		};
	// The newest upgrade, even one that a reorganisation can still remove: it is not kept.
	const newest = recent.logs.at(-1);
	if (newest) return implementationFromSlot(newest.topics[1]);

	// No upgrade in the new blocks: the kept answer stands, unless the search back is not complete.
	const { low } = entry.walk;
	if (low > fromBlock) {
		const older = await walkBack(
			getLogs,
			low - 1n,
			fromBlock,
			maxChunks - recent.requests,
		);
		const found = older.logs.at(-1);
		entry.walk = found
			? {
					checkpoint,
					implementation: implementationFromSlot(found.topics[1]),
					low: fromBlock,
				}
			: { checkpoint, implementation: null, low: older.low };
		// The blocks answered before a failed request are kept above: the next read continues below.
		if (older.failure) throw older.failure.error;
		if (!found && older.low > fromBlock)
			throw new UpgradedLogWalkLimitError(
				walkLimitMessage(
					older.low,
					latest,
					maxChunks,
					"Read again through the same client to continue the search further back",
				),
			);
	}
	return entry.walk.implementation;
}
