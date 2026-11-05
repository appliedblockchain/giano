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
 * Returns "unreadable" when a user operation's callData is not an execute or executeBatch call.
 * Its calls cannot be checked, and executeWithoutChainIdValidation is a self-call by
 * definition, so the host refuses it rather than guessing.
 */
export function checkSelfCall(
	method: string,
	params: unknown,
	account: string,
): SelfCallCheck {
	if (!OPERATION_METHODS.has(method)) return "none";
	const calls = operationCalls(method, params);
	if (calls === null) return "unreadable";
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

/** The calls of an operation request, or null when they cannot be read. */
function operationCalls(
	method: string,
	params: unknown,
): OperationCall[] | null {
	const args = Array.isArray(params) ? params : [];
	const first = args[0] as Record<string, unknown> | undefined;

	if (method === "eth_sendTransaction") {
		// A missing `to` is refused by the provider; there is no target to compare.
		return [{ to: first?.to, carriesCalldata: hasData(first?.data) }];
	}

	if (method === "eth_prepareUserOperation") {
		// The provider passes `{ calls, ...options }` to viem, so options can override the calls
		// or supply raw callData. Every source of calls is checked.
		const options = (args[1] ?? {}) as Record<string, unknown>;
		const calls = [...viemCalls(args[0]), ...viemCalls(options.calls)];
		if (options.callData !== undefined) {
			const decoded = decodeAccountCallData(options.callData);
			if (decoded === null) return null;
			calls.push(...decoded);
		}
		return calls;
	}

	// eth_signUserOperation, eth_sendSignedUserOperation: the operation's callData is what the
	// account executes.
	return decodeAccountCallData(first?.callData);
}

/** viem calls: `{ to, data }`, or `{ to, abi, functionName, args }` that viem encodes. */
function viemCalls(calls: unknown): OperationCall[] {
	if (!Array.isArray(calls)) return [];
	return calls.map((value) => {
		const call = (value ?? {}) as Record<string, unknown>;
		return {
			to: call.to,
			carriesCalldata:
				hasData(call.data) ||
				call.abi !== undefined ||
				call.functionName !== undefined,
		};
	});
}

/** Decodes the account's own execute / executeBatch callData into its calls. */
function decodeAccountCallData(callData: unknown): OperationCall[] | null {
	if (typeof callData !== "string") return null;
	try {
		const decoded = decodeFunctionData({
			abi: gianoSmartWalletAbi,
			data: callData as Hex,
		});
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
		return null;
	} catch {
		return null;
	}
}

/** Anything other than absent or empty data counts as calldata. */
function hasData(data: unknown): boolean {
	return !(data === undefined || data === null || data === "" || data === "0x");
}
