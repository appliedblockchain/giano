import { gianoSmartWalletAbi } from "@appliedblockchain/giano-contracts";
import { decodeFunctionData, type Hex } from "viem";

/**
 * The transport methods through which a dApp gets an operation of the user's account built,
 * signed or sent.
 */
export const OPERATION_METHODS: ReadonlySet<string> = new Set([
	"eth_sendTransaction",
	"eth_prepareUserOperation",
	"eth_signUserOperation",
	"eth_sendSignedUserOperation",
]);

export type SelfCallCheck = "none" | "self-call" | "unreadable";

/** One call of an operation: where it goes, and whether it carries calldata. */
type OperationCall = { to: unknown; carriesCalldata: boolean };

/** Thrown inside the reader when a value has a shape the check cannot trust. */
class Unreadable extends Error {}

/**
 * Whether a dApp request would make the user's account call one of its own functions.
 *
 * The wallet's onlyOwner accepts a call from the account to itself, so a self-call with
 * calldata can add or remove owners or upgrade the account. Only the wallet's own management
 * view may build one. A dApp gets one affordance for that: giano_openWalletManagement.
 *
 * A self-call with no calldata reaches only the wallet's empty receive(), so a plain value
 * transfer to self stays allowed.
 *
 * Returns "unreadable" when the request cannot be checked, and the caller refuses it:
 * - `params` is not an array. The provider unpacks any iterable, so a `Set` would carry a
 *   transaction this check never sees.
 * - The transaction, a call or the user operation is missing, null or not an object.
 * - A `to` or `data` is not a primitive string (or absent). A `String` object compares as
 *   "not the account" here but viem still encodes it as the account.
 * - A user operation's callData is not an execute or executeBatch call.
 *   executeWithoutChainIdValidation is a self-call by definition. callData "0x" executes
 *   nothing (a deploy-only user operation) and is allowed.
 */
export function checkSelfCall(
	method: string,
	params: unknown,
	account: string,
): SelfCallCheck {
	if (!OPERATION_METHODS.has(method)) return "none";
	let calls: OperationCall[];
	try {
		calls = operationCalls(method, params);
	} catch (error) {
		if (error instanceof Unreadable) return "unreadable";
		throw error;
	}
	const self = account.toLowerCase();
	return calls.some(
		(call) =>
			call.carriesCalldata &&
			typeof call.to === "string" &&
			call.to.toLowerCase() === self,
	)
		? "self-call"
		: "none";
}

/** The calls of an operation request. Throws Unreadable when they cannot be read. */
function operationCalls(method: string, params: unknown): OperationCall[] {
	if (!Array.isArray(params)) throw new Unreadable();

	if (method === "eth_sendTransaction") {
		// A missing `to` is refused by the provider; there is no target to compare.
		const transaction = object(params[0]);
		return [
			{
				to: address(transaction.to),
				carriesCalldata: hasData(transaction.data),
			},
		];
	}

	if (method === "eth_prepareUserOperation") {
		// The provider passes `{ calls, ...options }` to viem, so options can override the calls
		// or supply raw callData. Every source of calls is checked.
		const options = optionalObject(params[1]);
		const calls = [...viemCalls(params[0]), ...viemCalls(options.calls)];
		if (options.callData !== undefined) {
			calls.push(...decodeAccountCallData(options.callData));
		}
		return calls;
	}

	// eth_signUserOperation, eth_sendSignedUserOperation: the operation's callData is what the
	// account executes.
	return decodeAccountCallData(object(params[0]).callData);
}

/** viem calls: `{ to, data }`, or `{ to, abi, functionName, args }` that viem encodes. */
function viemCalls(calls: unknown): OperationCall[] {
	if (calls === undefined || calls === null) return [];
	if (!Array.isArray(calls)) throw new Unreadable();
	return calls.map((value) => {
		const call = object(value);
		return {
			to: address(call.to),
			carriesCalldata:
				hasData(call.data) ||
				call.abi !== undefined ||
				call.functionName !== undefined,
		};
	});
}

/**
 * Decodes the account's own execute / executeBatch callData into its calls. "0x" executes
 * nothing (a deploy-only user operation), so it has no calls.
 */
function decodeAccountCallData(callData: unknown): OperationCall[] {
	if (typeof callData !== "string") throw new Unreadable();
	if (callData === "0x") return [];
	const decoded = decodeWalletCall(callData as Hex);
	if (decoded.functionName === "execute") {
		const [to, , data] = decoded.args;
		return [{ to, carriesCalldata: hasData(data) }];
	}
	if (decoded.functionName === "executeBatch") {
		return decoded.args[0].map((call) => ({
			to: call.target,
			carriesCalldata: hasData(call.data),
		}));
	}
	throw new Unreadable();
}

/** The wallet function a callData calls. Throws Unreadable when it is not one. */
function decodeWalletCall(data: Hex) {
	try {
		return decodeFunctionData({ abi: gianoSmartWalletAbi, data });
	} catch {
		throw new Unreadable();
	}
}

/**
 * A plain object's fields. A transaction, a call or a user operation must be one: a missing or
 * null entry is unreadable, because the consent screen and the provider cannot use it either.
 */
function object(value: unknown): Record<string, unknown> {
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		throw new Unreadable();
	}
	return value as Record<string, unknown>;
}

/** Optional fields, such as the options of eth_prepareUserOperation: absent counts as empty. */
function optionalObject(value: unknown): Record<string, unknown> {
	return value === undefined || value === null ? {} : object(value);
}

/** A call target: absent, or a primitive string. */
function address(value: unknown): unknown {
	if (value === undefined || value === null || typeof value === "string") {
		return value;
	}
	throw new Unreadable();
}

/** Absent or empty data carries no calldata; a primitive string carries some; anything else is unreadable. */
function hasData(data: unknown): boolean {
	if (data === undefined || data === null || data === "" || data === "0x") {
		return false;
	}
	if (typeof data === "string") return true;
	throw new Unreadable();
}
