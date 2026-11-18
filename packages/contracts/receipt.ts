/**
 * Waiting for a transaction receipt on an RPC that refuses full blocks.
 *
 * When a receipt is not there yet, viem's `waitForTransactionReceipt` checks whether the transaction
 * was replaced (the same nonce sent again): it asks for the block with its transactions,
 * `eth_getBlockByNumber` with `true`. The Silent Data gateway refuses that parameter ("param values
 * not whitelisted for JSON RPC method", -107486), and the wait fails although the transaction was
 * mined. {@link waitForReceipt} waits as viem does, and only when the RPC refused that full-block
 * request waits again without the replacement check, polling `eth_getTransactionReceipt` alone. A
 * full-block request that failed for another reason, such as an HTTP 429 or 503, is thrown. On an RPC
 * that returns full blocks nothing changes. This decides by the request that failed, as
 * `proxyImplementationWithSource` does for `eth_getStorageAt`, not by which chain it is.
 */

/** The JSON-RPC methods that return a block, whose second parameter `true` asks for its transactions. */
const BLOCK_METHODS = new Set(["eth_getBlockByNumber", "eth_getBlockByHash"]);

/** viem's `RpcRequestError` keeps the request only in this line of its `metaMessages`. */
const REQUEST_BODY_PREFIX = "Request body: ";

function asksForFullBlock(body: unknown): boolean {
	if (Array.isArray(body)) return body.some(asksForFullBlock);
	if (!body || typeof body !== "object") return false;
	const { method, params } = body as { method?: unknown; params?: unknown };
	return (
		typeof method === "string" &&
		BLOCK_METHODS.has(method) &&
		Array.isArray(params) &&
		params[1] === true
	);
}

function bodyFromMetaMessages(metaMessages: unknown): unknown {
	if (!Array.isArray(metaMessages)) return undefined;
	for (const line of metaMessages) {
		if (typeof line !== "string" || !line.startsWith(REQUEST_BODY_PREFIX))
			continue;
		try {
			return JSON.parse(line.slice(REQUEST_BODY_PREFIX.length));
		} catch {
			return undefined;
		}
	}
	return undefined;
}

/**
 * True when the error comes from a request for a block with its transactions: viem's
 * `HttpRequestError` keeps the request as `body`, its `RpcRequestError` in `metaMessages`. Follows
 * the `cause` chain. False for every other failure, which a fallback would only hide.
 */
export function isFullBlockRequestError(error: unknown): boolean {
	let current: unknown = error;
	for (let depth = 0; depth < 8 && current; depth++) {
		if (typeof current !== "object") return false;
		const record = current as Record<string, unknown>;
		if (
			asksForFullBlock(record.body) ||
			asksForFullBlock(bodyFromMetaMessages(record.metaMessages))
		)
			return true;
		current = record.cause;
	}
	return false;
}

/** The Silent Data gateway's refusal of a parameter value: code -107486, "param values not whitelisted…". */
const PARAM_REFUSED_CODE = -107486;
const PARAM_REFUSED_MESSAGE = /\bnot whitelisted\b/i;

/**
 * True when the error says the RPC refused the request: the gateway's code or message, as viem's
 * `RpcRequestError` carries it (HTTP 200), or in the `details` of its `HttpRequestError` (HTTP 403).
 * Follows the `cause` chain. False for a rate limit, an unavailable RPC or any other failure.
 */
function isRefusal(error: unknown): boolean {
	let current: unknown = error;
	for (let depth = 0; depth < 8 && current; depth++) {
		if (typeof current !== "object") return false;
		const record = current as Record<string, unknown>;
		if (record.code === PARAM_REFUSED_CODE) return true;
		for (const text of [record.shortMessage, record.details, record.message])
			if (typeof text === "string" && PARAM_REFUSED_MESSAGE.test(text))
				return true;
		current = record.cause;
	}
	return false;
}

export type WaitForReceiptParameters = {
	hash: `0x${string}`;
	confirmations?: number;
	timeout?: number;
	pollingInterval?: number;
};

/**
 * `client.waitForTransactionReceipt`, which waits again without its replacement check when the RPC
 * refused the full block that check asked for. A replaced transaction is then not reported as
 * replaced: the wait times out instead. Every other failure is thrown as it is, including a
 * full-block request that failed without a refusal.
 */
export async function waitForReceipt<Receipt>(
	client: {
		waitForTransactionReceipt(
			parameters: WaitForReceiptParameters & { checkReplacement?: boolean },
		): Promise<Receipt>;
	},
	parameters: WaitForReceiptParameters,
): Promise<Receipt> {
	try {
		return await client.waitForTransactionReceipt(parameters);
	} catch (error) {
		if (!isFullBlockRequestError(error) || !isRefusal(error)) throw error;
		return client.waitForTransactionReceipt({
			...parameters,
			checkReplacement: false,
		});
	}
}
