import type { FastifyBaseLogger } from "fastify";
import { z } from "zod";
import type { ChainServices } from "./chains.js";
import { NodeRpcError } from "./node-rpc.js";

/**
 * The read relay's core, behind two doors: the tenant relay (`/v1/rpc`, tenant-bound by Origin)
 * and the platform relay (`/v1/platform/rpc/:chainId`, platform admin session). Each door decides
 * who is calling and which key their rate window is counted under; what may be forwarded, and how
 * the node's answer comes back, is decided here once.
 *
 * Read-only by construction: the allowlist is the whole contract.
 */

/** What viem's public client and the wallet's own reads actually call. Nothing that spends or mutates. */
export const READ_METHODS = new Set([
	"eth_call",
	"eth_getCode",
	"eth_getBalance",
	"eth_getStorageAt",
	"eth_getTransactionCount",
	"eth_estimateGas",
	"eth_gasPrice",
	"eth_maxPriorityFeePerGas",
	"eth_feeHistory",
	"eth_blockNumber",
	"eth_getBlockByNumber",
	"eth_getBlockByHash",
	"eth_getTransactionByHash",
	"eth_getTransactionReceipt",
	"eth_getLogs",
	"net_version",
]);

const jsonRpcId = z.union([z.string(), z.number(), z.null()]);

/** One request object. A batch array fails this, which is the point: one call, one slot. */
export const jsonRpcRequestSchema = z.object({
	jsonrpc: z.literal("2.0"),
	id: jsonRpcId,
	method: z.string(),
	params: z.array(z.unknown()).optional(),
});

export const jsonRpcResponseSchema = z.object({
	jsonrpc: z.literal("2.0"),
	id: jsonRpcId,
	result: z.unknown().optional(),
	error: z
		.object({
			code: z.number(),
			message: z.string(),
			data: z.unknown().optional(),
		})
		.optional(),
});

/** `-32601`/`-32602`/`-32603` are JSON-RPC's own; `-32021`/`-32023` mean what they mean on `/v1/bundler`. */
const CODES = {
	"method-not-found": -32601,
	"invalid-params": -32602,
	internal: -32603,
	"rate-limited": -32021,
	"node-unavailable": -32023,
} as const;

export type JsonRpcRequest = z.infer<typeof jsonRpcRequestSchema>;
export type JsonRpcResponse = z.infer<typeof jsonRpcResponseSchema>;

export type RelayOutcome = keyof typeof CODES | "ok" | "node-error";

/** Labels every count carries; `extra` is whatever the door adds (the tenant, for the tenant relay). */
export type RelayLabels<Extra> = Extra & {
	method: string;
	chain: string;
	outcome: RelayOutcome;
};

export type ReadRelayOptions<Extra> = {
	limitPerMinute: number;
	/** What a caller over its limit is told. The door knows whose limit it is. */
	limitMessage: string;
	/**
	 * A door's own refusal for a request the allowlist admits — its params, not its method.
	 * Returns the reason to refuse with (`-32602`), or undefined to forward. Runs before the rate
	 * window, so a refused request costs no slot.
	 */
	guard?: (method: string, params: unknown[]) => string | undefined;
	count: (labels: RelayLabels<Extra>) => void;
};

/** Windows untouched for longer than this are dropped when the map grows; a key is a tenant or a session. */
const WINDOW_MS = 60_000;
const SWEEP_AT = 1024;

export function createReadRelay<Extra extends object = object>(
	opts: ReadRelayOptions<Extra>,
) {
	const windows = new Map<string, { windowStart: number; count: number }>();
	const takeSlot = (key: string): boolean => {
		const now = Date.now();
		const window = windows.get(key);
		if (!window || now - window.windowStart >= WINDOW_MS) {
			if (!window && windows.size >= SWEEP_AT) {
				for (const [stale, entry] of windows)
					if (now - entry.windowStart >= WINDOW_MS) windows.delete(stale);
			}
			windows.set(key, { windowStart: now, count: 1 });
			return true;
		}
		window.count += 1;
		return window.count <= opts.limitPerMinute;
	};

	return {
		async handle({
			body,
			chain,
			key,
			log,
			labels: extra,
		}: {
			body: JsonRpcRequest;
			chain: ChainServices;
			/** Whose rate window this call counts against. */
			key: string;
			log: FastifyBaseLogger;
			labels: Extra;
		}): Promise<JsonRpcResponse> {
			const { id, method, params = [] } = body;
			const labels = { ...extra, method, chain: String(chain.chainId) };

			const ok = (result: unknown): JsonRpcResponse => {
				opts.count({ ...labels, outcome: "ok" });
				return { jsonrpc: "2.0", id, result };
			};
			const fail = (
				reason: keyof typeof CODES,
				message: string,
			): JsonRpcResponse => {
				opts.count({ ...labels, outcome: reason });
				return { jsonrpc: "2.0", id, error: { code: CODES[reason], message } };
			};

			if (method === "eth_chainId")
				return ok(`0x${chain.chainId.toString(16)}`);

			if (!READ_METHODS.has(method)) {
				return fail(
					"method-not-found",
					`${method} is not relayed — this endpoint forwards read-only chain methods and nothing else`,
				);
			}
			const refusal = opts.guard?.(method, params);
			if (refusal) return fail("invalid-params", refusal);
			if (!takeSlot(key)) return fail("rate-limited", opts.limitMessage);
			try {
				return ok(await chain.nodeRpc.call(method, params));
			} catch (error) {
				if (error instanceof NodeRpcError) {
					// The node's own answer, code and all — a revert reason must reach the caller intact.
					opts.count({ ...labels, outcome: "node-error" });
					return {
						jsonrpc: "2.0",
						id,
						error: {
							code: error.code,
							message: error.message,
							...(error.data === undefined ? {} : { data: error.data }),
						},
					};
				}
				log.error(
					{ err: error, method, chainId: chain.chainId },
					"rpc relay: node unreachable",
				);
				return fail("node-unavailable", "the chain RPC could not be reached");
			}
		},
	};
}

const HEX_QUANTITY = /^0x[0-9a-fA-F]+$/;

/**
 * Bounds `eth_getLogs` to what a log window can cost: a single block by hash, or a numeric range
 * of at most `maxBlocks`. Block tags are refused because their span cannot be known without asking
 * the node for the head — and `earliest`→`latest` is exactly the query this exists to stop.
 */
export function boundedLogsGuard(maxBlocks: number) {
	const limit = `eth_getLogs must name a blockHash, or hex fromBlock and toBlock spanning at most ${maxBlocks} blocks`;
	return (method: string, params: unknown[]): string | undefined => {
		if (method !== "eth_getLogs") return undefined;
		const filter = params[0] as
			| { blockHash?: unknown; fromBlock?: unknown; toBlock?: unknown }
			| undefined;
		if (!filter || typeof filter !== "object") return limit;
		if (typeof filter.blockHash === "string") {
			// A blockHash filter is one block by definition; a range alongside it is malformed.
			return filter.fromBlock === undefined && filter.toBlock === undefined
				? undefined
				: limit;
		}
		const { fromBlock, toBlock } = filter;
		if (
			typeof fromBlock !== "string" ||
			typeof toBlock !== "string" ||
			!HEX_QUANTITY.test(fromBlock) ||
			!HEX_QUANTITY.test(toBlock)
		)
			return limit;
		const span = BigInt(toBlock) - BigInt(fromBlock) + 1n;
		return span <= BigInt(maxBlocks) ? undefined : limit;
	};
}
