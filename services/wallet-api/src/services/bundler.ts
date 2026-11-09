import type { Address } from "viem";
import { postJsonRpc, type UpstreamLimits } from "./upstream-fetch.js";

/**
 * Minimal JSON-RPC client for the ERC-4337 bundler. The EntryPoint address is ALWAYS
 * the server-configured one — never anything from a request body.
 *
 * Every call is bounded in time and response size (`limits`, G37). A call that hits a limit
 * throws `UpstreamLimitError`.
 */
export function createBundlerService(
	bundlerUrl: string,
	entryPoint: Address,
	{
		limits,
		fetchImpl = fetch,
	}: { limits: UpstreamLimits; fetchImpl?: typeof fetch },
) {
	let rpcId = 0;

	async function rpc<T>(
		method: string,
		params: unknown[],
		signal?: AbortSignal,
	): Promise<T> {
		const body = (await postJsonRpc(
			bundlerUrl,
			{ jsonrpc: "2.0", id: ++rpcId, method, params },
			{ upstream: "bundler", limits, fetchImpl, signal },
		)) as {
			result?: T;
			error?: { code: number; message: string };
		};
		if (body.error) {
			throw new BundlerRpcError(body.error.code, body.error.message);
		}
		return body.result as T;
	}

	return {
		entryPoint,
		/** rpcUserOp fields must already be hex-encoded (RpcUserOperation shape). */
		sendUserOperation: (rpcUserOp: Record<string, unknown>) =>
			rpc<string>("eth_sendUserOperation", [rpcUserOp, entryPoint]),
		estimateUserOperationGas: (rpcUserOp: Record<string, unknown>) =>
			rpc<Record<string, unknown>>("eth_estimateUserOperationGas", [
				rpcUserOp,
				entryPoint,
			]),
		getUserOperationReceipt: (hash: string) =>
			rpc<Record<string, unknown> | null>("eth_getUserOperationReceipt", [
				hash,
			]),
		getUserOperationByHash: (hash: string) =>
			rpc<Record<string, unknown> | null>("eth_getUserOperationByHash", [hash]),
		/**
		 * The EntryPoints the bundler itself says it serves. The wallet relay answers
		 * `eth_supportedEntryPoints` from configuration; this asks the bundler, for chain status (B3).
		 * `signal` bounds the request itself, not only how long the caller waits for it.
		 */
		supportedEntryPoints: (signal?: AbortSignal) =>
			rpc<Address[]>("eth_supportedEntryPoints", [], signal),
		/**
		 * giano-bundler's executor lanes on this chain and the chain's gas price, as hex (B7). Not
		 * ERC-4337: a bundler without it (Alto) answers method-not-found.
		 */
		executors: (signal?: AbortSignal) =>
			rpc<unknown>("giano_executors", [], signal),
	};
}

export class BundlerRpcError extends Error {
	constructor(
		public readonly code: number,
		message: string,
	) {
		super(message);
		this.name = "BundlerRpcError";
	}
}

export type BundlerService = ReturnType<typeof createBundlerService>;
