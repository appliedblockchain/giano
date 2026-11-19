import { postJsonRpc, type UpstreamLimits } from "./upstream-fetch.js";

/**
 * Minimal JSON-RPC client for a chain's node, used by the read relay. Kept separate from the
 * viem `publicClient` so that a wallet's request is forwarded verbatim — method, params and
 * the node's own error — rather than re-encoded.
 *
 * Every call is bounded in time and response size (`limits`, G37). A call that hits a limit
 * throws `UpstreamLimitError`.
 */
export function createNodeRpcService(
	rpcUrl: string,
	{
		limits,
		fetchImpl = fetch,
	}: { limits: UpstreamLimits; fetchImpl?: typeof fetch },
) {
	let rpcId = 0;

	return {
		async call(method: string, params: unknown[]): Promise<unknown> {
			const body = (await postJsonRpc(
				rpcUrl,
				{ jsonrpc: "2.0", id: ++rpcId, method, params },
				{
					upstream: "node",
					limits,
					fetchImpl,
					passErrorBody: (error) => error.code === GATEWAY_REFUSAL_CODE,
				},
			)) as {
				result?: unknown;
				error?: { code: number; message: string; data?: unknown };
			};
			if (body.error) {
				throw new NodeRpcError(
					body.error.code,
					body.error.message,
					body.error.data,
				);
			}
			return body.result;
		},
	};
}

/**
 * The Silent Data gateway's refusal of a parameter value, sent with HTTP 403. The relay passes only
 * this non-2xx error through, so `wait()` in the SDK can fall back. Any other non-2xx answer (a rate
 * limit, a revoked key, an outage) stays "node unreachable": logged, and `-32023` to the caller.
 */
const GATEWAY_REFUSAL_CODE = -107486;

export class NodeRpcError extends Error {
	constructor(
		public readonly code: number,
		message: string,
		public readonly data?: unknown,
	) {
		super(message);
		this.name = "NodeRpcError";
	}
}

export type NodeRpcService = ReturnType<typeof createNodeRpcService>;
