import { BaseError, decodeErrorResult, type Hex, isHex } from "viem";
import { entryPoint09Abi } from "viem/account-abstraction";

/**
 * JSON-RPC error codes. The 4337 ones are ERC-7769's, with the meanings Alto gave them, so a
 * client that keyed behaviour off Alto's codes sees the same codes here.
 */
export const ERROR_CODES = {
	parseError: -32700,
	invalidRequest: -32600,
	methodNotFound: -32601,
	invalidParams: -32602,
	internal: -32603,
	/** Rejected by the EntryPoint or the account during validation. */
	validationReverted: -32500,
	/** Rejected by the paymaster during validation. */
	paymasterRejected: -32501,
	/** Valid only outside the current time window. */
	outOfTimeRange: -32503,
	invalidSignature: -32507,
	/** The operation's execution reverted during estimation. */
	executionReverted: -32521,
} as const;

export class RpcError extends Error {
	constructor(
		public readonly code: number,
		message: string,
		public readonly data?: unknown,
	) {
		super(message);
		this.name = "RpcError";
	}
}

/** The revert payload of a failed call, wherever this node and viem put it. */
export function revertData(error: unknown): Hex | undefined {
	const seen = new Set<unknown>();
	const visit = (value: unknown): Hex | undefined => {
		if (!value || typeof value !== "object" || seen.has(value))
			return undefined;
		seen.add(value);
		const record = value as Record<string, unknown>;
		if (isHex(record.data) && record.data.length >= 10) return record.data;
		if (record.data && typeof record.data === "object") {
			const nested = visit(record.data);
			if (nested) return nested;
		}
		return visit(record.cause);
	};
	return visit(error);
}

export type EntryPointRevert =
	/** `FailedOp` / `FailedOpWithRevert`: the "AAxx …" reason and, for the latter, the inner revert. */
	| { kind: "failed-op"; reason: string; inner?: Hex }
	| { kind: "other"; message: string };

/** Decodes what the EntryPoint (or EntryPointSimulations) reverted with. */
export function decodeEntryPointRevert(error: unknown): EntryPointRevert {
	const data = revertData(error);
	if (data) {
		try {
			const decoded = decodeErrorResult({ abi: entryPoint09Abi, data });
			if (decoded.errorName === "FailedOp")
				return { kind: "failed-op", reason: decoded.args[1] };
			if (decoded.errorName === "FailedOpWithRevert")
				return {
					kind: "failed-op",
					reason: decoded.args[1],
					inner: decoded.args[2],
				};
			return {
				kind: "other",
				message: `${decoded.errorName}(${decoded.args?.map(String).join(", ") ?? ""})`,
			};
		} catch {
			return { kind: "other", message: `reverted with ${data}` };
		}
	}
	return {
		kind: "other",
		message:
			error instanceof BaseError
				? error.shortMessage
				: ((error as Error)?.message ?? String(error)),
	};
}

/** The 4337 error for an operation the EntryPoint refused while validating it. */
export function validationError(revert: EntryPointRevert): RpcError {
	if (revert.kind === "other")
		return new RpcError(
			ERROR_CODES.validationReverted,
			`UserOperation reverted with reason: ${revert.message}`,
		);
	const message = `UserOperation reverted with reason: ${revert.reason}${revert.inner && revert.inner !== "0x" ? ` - ${revert.inner}` : ""}`;
	const code = revert.reason.slice(0, 4);
	if (code === "AA24" || code === "AA34")
		return new RpcError(ERROR_CODES.invalidSignature, message);
	if (code === "AA22" || code === "AA32")
		return new RpcError(ERROR_CODES.outOfTimeRange, message);
	if (code === "AA25") return new RpcError(ERROR_CODES.invalidParams, message);
	if (code.startsWith("AA3"))
		return new RpcError(ERROR_CODES.paymasterRejected, message);
	return new RpcError(ERROR_CODES.validationReverted, message);
}

/** The 4337 error for an operation that could not be simulated during estimation. */
export function simulationError(reason: string): RpcError {
	const message = `UserOperation reverted during simulation with reason: ${reason}`;
	return new RpcError(
		reason.includes("AA23")
			? ERROR_CODES.validationReverted
			: ERROR_CODES.executionReverted,
		message,
	);
}
