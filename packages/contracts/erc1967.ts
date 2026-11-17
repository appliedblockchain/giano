/**
 * ERC-1967 proxies (the paymaster proxy): which implementation a proxy delegates to. One reader for
 * the deploy tooling, giano-doctor and wallet-api, whatever client they use.
 */
import { type Address, getAddress, type Hex, type PublicClient } from "viem";

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

/** Bounds on the backwards walk through a proxy's `Upgraded` logs. */
export type UpgradedLogWalkOptions = {
	/** The lowest block to search, such as the proxy's deployment block. Default 0. */
	fromBlock?: bigint;
	/** The most `eth_getLogs` requests the walk sends. Default {@link UPGRADED_LOG_MAX_CHUNKS}. */
	maxChunks?: number;
};

/** The walk sent `maxChunks` requests, did not reach `fromBlock`, and found no `Upgraded` event. */
class UpgradedLogWalkLimitError extends Error {
	constructor(fromBlock: bigint, toBlock: bigint, maxChunks: number) {
		super(
			`no Upgraded event in blocks ${fromBlock}-${toBlock}, and the walk stops after ${maxChunks} eth_getLogs requests. Pass fromBlock (the proxy's deployment block) or a larger maxChunks to search further back`,
		);
		this.name = "UpgradedLogWalkLimitError";
	}
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
 * `getLogs` returns the topics of the proxy's `Upgraded` logs in [fromBlock, toBlock], oldest first.
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
	let chunks = 0;
	for (let to = latest; to >= fromBlock; to -= UPGRADED_LOG_CHUNK) {
		if (chunks === maxChunks)
			throw new UpgradedLogWalkLimitError(to + 1n, latest, maxChunks);
		chunks++;
		const from =
			to - fromBlock >= UPGRADED_LOG_CHUNK - 1n
				? to - UPGRADED_LOG_CHUNK + 1n
				: fromBlock;
		const logs = await getLogs(from, to);
		const last = logs.at(-1);
		if (last) return implementationFromSlot(last.topics[1]);
	}
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

/** What the last log walk for a proxy found, up to which block. */
type Walked = {
	block: bigint;
	implementation: Address | null;
	/** The walk gave up. Raised again until a newer block holds an upgrade. */
	limit?: UpgradedLogWalkLimitError;
};

/**
 * Per client, then per proxy: the result of the last log walk. A later read walks only the blocks
 * after it, so a caller that reads on every block (the console's health check) sends one
 * `eth_getLogs`, not the whole walk again. Keyed by the client object, so it lives as long as the
 * client does.
 */
const walks = new WeakMap<object, Map<Address, Walked>>();

/**
 * The implementation the ERC-1967 proxy at `proxy` delegates to, or null when its slot is empty.
 * Reads the slot. When the RPC refuses that method and the client can read logs, it falls back to
 * the latest `Upgraded` event, bounded by `options`. Any other storage-read error is raised
 * unchanged. When the fallback fails too, the error names both failures, with the storage-read
 * error as `cause`.
 */
export async function proxyImplementation(
	client: Pick<PublicClient, "getStorageAt"> &
		Partial<Pick<PublicClient, "getBlockNumber" | "request">>,
	proxy: Address,
	options: UpgradedLogWalkOptions = {},
): Promise<Address | null> {
	try {
		return implementationFromSlot(
			await client.getStorageAt({ address: proxy, slot: IMPLEMENTATION_SLOT }),
		);
	} catch (storageError) {
		const { getBlockNumber, request } = client;
		if (!getBlockNumber || !request || !isMethodRefusedError(storageError))
			throw storageError;
		try {
			return await implementationSinceLastWalk(
				client,
				proxy,
				options,
				await getBlockNumber(),
				(fromBlock, toBlock) =>
					request({
						method: "eth_getLogs",
						params: [
							{
								address: proxy,
								topics: [UPGRADED_TOPIC],
								fromBlock: `0x${fromBlock.toString(16)}`,
								toBlock: `0x${toBlock.toString(16)}`,
							},
						],
					}) as Promise<readonly { topics: readonly (string | null)[] }[]>,
			);
		} catch (logError) {
			throw new Error(
				`could not read the implementation of ${proxy}: the RPC refused eth_getStorageAt, and reading its Upgraded logs failed: ${logError instanceof Error ? logError.message : String(logError)}`,
				{ cause: storageError },
			);
		}
	}
}

/** The log walk, from the block after this client's last walk for `proxy` when there was one. */
async function implementationSinceLastWalk(
	client: object,
	proxy: Address,
	options: UpgradedLogWalkOptions,
	latest: bigint,
	getLogs: Parameters<typeof implementationFromUpgradedLogs>[0],
): Promise<Address | null> {
	let byProxy = walks.get(client);
	if (!byProxy) {
		byProxy = new Map();
		walks.set(client, byProxy);
	}
	const key = getAddress(proxy);
	let walked = byProxy.get(key);

	if (!walked || latest > walked.block) {
		const floor = options.fromBlock ?? 0n;
		const next =
			walked && walked.block + 1n > floor ? walked.block + 1n : floor;
		let found: Address | null;
		try {
			found = await implementationFromUpgradedLogs(getLogs, latest, {
				...options,
				fromBlock: next,
			});
		} catch (error) {
			if (error instanceof UpgradedLogWalkLimitError)
				byProxy.set(key, { block: latest, implementation: null, limit: error });
			throw error;
		}
		// No upgrade in the new blocks: the last walk's answer stands. An Upgraded event never names
		// the zero address, as ERC-1967 refuses an implementation without code.
		walked =
			found === null && walked
				? { ...walked, block: latest }
				: { block: latest, implementation: found };
		byProxy.set(key, walked);
	}
	if (walked.limit) throw walked.limit;
	return walked.implementation;
}
