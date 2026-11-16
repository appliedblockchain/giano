import { gianoSmartWalletAbi } from "@appliedblockchain/giano-contracts";
import type { Address, Hex } from "viem";
import {
	decodeFunctionData,
	getAbiItem,
	size,
	slice,
	toFunctionSelector,
} from "viem";
import {
	type SponsorshipConfig,
	walletManagementEnabled,
} from "./sponsorship-config.js";

/**
 * The sponsorship rules engine.
 *
 * A pure function, no I/O. That is what lets the wallet's pre-approval check and the
 * authoritative pre-signature check share one implementation — two implementations of the same
 * rules would drift, and the drift would show up as a transaction refused after the user had
 * already been asked to approve it.
 *
 * Every rule is recorded whether it passed or not, even after the decision is settled, because
 * "why was this refused" has to be answerable without re-running anything.
 */

export type SponsorshipRuleResult = {
	rule: string;
	passed: boolean;
	detail?: string;
};

/** Stable, machine-readable refusal reasons. The wallet keys its copy off these, never off prose. */
export type SponsorshipRefusalReason =
	| "sponsorship-disabled"
	| "no-sponsorship-config"
	| "contract-not-allowed"
	| "function-not-allowed"
	| "wallet-management-not-sponsored"
	| "cost-exceeds-cap"
	| "insufficient-balance"
	| "tenant-in-deficit"
	| "not-your-wallet";

export type SponsorshipDecision = {
	allowed: boolean;
	results: SponsorshipRuleResult[];
	reason?: SponsorshipRefusalReason;
	detail?: string;
	/** What the operation would cost the tenant in total: gas + fee + overhead. */
	maxChargeWei: bigint;
	feeWei: bigint;
	overheadWei: bigint;
	/** The per-transaction cap that applied — the tenant's own, the platform's, or the lower of both. */
	capWei?: bigint;
	/**
	 * Where that cap came from. Recorded because "how much are we spending on wallet management, and
	 * for whom" has to be answerable from the decision table before the question of who pays for it
	 * is decided, not after.
	 */
	capSource?: "tenant" | "platform" | "wallet-management-tenant";
	/**
	 * True when the operation contains a call from the wallet to itself that is sponsored as wallet
	 * management: a call that adds or removes an owner, or a plain value transfer to self (see
	 * `classifyCall`). Not every operation with this flag changes the owner set.
	 */
	isWalletManagement: boolean;
};

export type CandidateOperation = {
	sender: Address;
	callData: Hex;
	callGasLimit: bigint;
	verificationGasLimit: bigint;
	preVerificationGas: bigint;
	maxFeePerGas: bigint;
	paymasterVerificationGasLimit: bigint;
	paymasterPostOpGasLimit: bigint;
	/** Present only when the operation also deploys the account. Part of the operation's hash. */
	factory?: Address;
	factoryData?: Hex;
};

/** What the ledger knows, at the moment of asking. */
export type BalanceView = {
	balanceWei: bigint;
	reservedWei: bigint;
	deficitWei: bigint;
};

export type OverheadParams = {
	/** Gas units the settlement step's own execution is charged at. */
	postOpGasAllowance: bigint;
	/** Basis points of the execution gas limits charged as a bound on the EntryPoint's penalty. */
	penaltyBps: bigint;
};

export type EvaluationInput = {
	candidate: CandidateOperation;
	config: SponsorshipConfig;
	balance: BalanceView;
	/** The fee in force for this tenant, read from the contract so what is pinned is what is charged. */
	feeWei: bigint;
	overhead: OverheadParams;
	/**
	 * The platform's cap on wallet-management operations.
	 *
	 * Platform configuration, not the tenant's, because wallet management is sponsored whatever the
	 * tenant's allowlist says — so the tenant cannot be the only thing bounding it. A tenant may
	 * lower this figure and never raise it.
	 */
	walletManagementCapWei: bigint;
	/** The wallet address the session's credential owns. */
	sessionWalletAddress: Address;
	/** True when the stored configuration failed to parse, which is not the same as it being off. */
	configUnparseable?: boolean;
};

/**
 * Mirrors the EntryPoint's own prefund arithmetic. Getting this wrong in the *optimistic*
 * direction would reserve less than the chain can charge, which is how a balance overdraws.
 */
export function computeMaxCost(candidate: CandidateOperation): bigint {
	const verificationGas =
		candidate.verificationGasLimit +
		candidate.paymasterVerificationGasLimit +
		candidate.paymasterPostOpGasLimit;
	return (
		(candidate.preVerificationGas + verificationGas + candidate.callGasLimit) *
		candidate.maxFeePerGas
	);
}

/**
 * The same formula the contract applies at settlement, so the reservation and the eventual charge
 * cannot drift apart in shape. Charging a bound on the penalty rather than a flat figure is what
 * makes it hold when a client grossly over-estimates its call gas — which is precisely the case
 * that drives the penalty.
 */
export function computeOverheadBound(
	candidate: CandidateOperation,
	overhead: OverheadParams,
): bigint {
	const executionGasLimit =
		candidate.callGasLimit + candidate.paymasterPostOpGasLimit;
	return (
		candidate.maxFeePerGas *
		(overhead.postOpGasAllowance +
			(executionGasLimit * overhead.penaltyBps) / 10_000n)
	);
}

/** One call of the operation. `empty` is true when the call carries no calldata at all. */
type InnerCall = {
	target: Address;
	value: bigint;
	selector: Hex | null;
	empty: boolean;
};

/**
 * Decodes the account's own `execute` / `executeBatch` calldata.
 *
 * Anything else is refused rather than guessed: an operation whose targets we cannot read is an
 * operation whose allowlist we cannot check, and guessing would mean sponsoring it.
 */
export function decodeInnerCalls(callData: Hex): InnerCall[] | null {
	try {
		const decoded = decodeFunctionData({
			abi: gianoSmartWalletAbi,
			data: callData,
		});
		if (decoded.functionName === "execute") {
			const [target, value, data] = decoded.args as readonly [
				Address,
				bigint,
				Hex,
			];
			return [
				{ target, value, selector: selectorOf(data), empty: size(data) === 0 },
			];
		}
		if (decoded.functionName === "executeBatch") {
			const calls = decoded.args[0] as readonly {
				target: Address;
				value: bigint;
				data: Hex;
			}[];
			return calls.map((call) => ({
				target: call.target,
				value: call.value,
				selector: selectorOf(call.data),
				empty: size(call.data) === 0,
			}));
		}
		return null;
	} catch {
		return null;
	}
}

function selectorOf(data: Hex): Hex | null {
	return size(data) >= 4 ? (slice(data, 0, 4).toLowerCase() as Hex) : null;
}

/**
 * The only wallet functions a self-call can use to be sponsored as wallet management: adding and
 * removing owners.
 *
 * This is a list of allowed functions, not a list of refused ones. `MultiOwnable` accepts
 * `msg.sender == address(this)`, and several wallet functions run calls or code they carry as a
 * payload:
 *
 * - `execute`, `executeBatch` and `executeWithoutChainIdValidation` run the calls they wrap.
 * - `upgradeToAndCall` delegatecalls its payload as the wallet, and can switch the wallet to any
 *   implementation.
 * - `signedStaticCall` calls any target with any calldata.
 *
 * A self-call to one of these runs calls the allowlist never sees, and the tenant pays for them.
 * A list of refused functions misses the next such function. This list refuses it by default.
 *
 * The list holds only the functions the product sends (`packages/wallet-core/src/management/owners.ts`).
 * `removeLastOwner` is not in it: it leaves the wallet with no owner, so it locks the wallet for
 * good, and wallet-kit refuses to build it (WM-28). Sponsoring it would only let a user make the
 * tenant pay to lock a wallet.
 *
 * The cost: a self-administration function added to the wallet later is not sponsored until it is
 * added here. That failure is safe. The user is asked to pay gas, and the tenant's balance is not
 * at risk.
 */
export const OWNER_MANAGEMENT_SELECTORS: ReadonlySet<Hex> = new Set(
	(["addOwnerAddress", "addOwnerPublicKey", "removeOwnerAtIndex"] as const).map(
		(name) =>
			toFunctionSelector(getAbiItem({ abi: gianoSmartWalletAbi, name })),
	),
);

/**
 * What one call of the operation is, for the rules below. Each call is classified once, and every
 * rule reads that result, so the rules cannot disagree about a call.
 *
 * - `application`: a call to any other address. The tenant's allowlists govern it.
 * - `wallet-management`: a self-call sponsored as wallet management. Two kinds:
 *   - A call to one of `OWNER_MANAGEMENT_SELECTORS` with no value. These functions are not
 *     payable, so a call with value always reverts, and the tenant would pay for an operation
 *     that cannot succeed.
 *   - A plain value transfer to self, with calldata of exactly `0x`. It reaches only the wallet's
 *     empty `receive()` (solady `Receiver`), so it runs no payload. wallet-kit allows the same
 *     call (`packages/wallet-kit/src/self-calls.ts`).
 * - `refused-self-call`: any other self-call. It may run a payload the allowlist cannot check.
 *   Calldata of 1 to 3 bytes has no selector but reaches the wallet's `fallback`, so it is not a
 *   plain transfer and lands here.
 */
type CallKind = "application" | "wallet-management" | "refused-self-call";

function classifyCall(call: InnerCall, sender: Address): CallKind {
	if (call.target.toLowerCase() !== sender.toLowerCase()) return "application";
	if (call.empty) return "wallet-management";
	if (
		call.value === 0n &&
		call.selector !== null &&
		OWNER_MANAGEMENT_SELECTORS.has(call.selector)
	) {
		return "wallet-management";
	}
	return "refused-self-call";
}

export function evaluateSponsorship(
	input: EvaluationInput,
): SponsorshipDecision {
	const { candidate, config, balance, feeWei, overhead, sessionWalletAddress } =
		input;

	const results: SponsorshipRuleResult[] = [];
	const pass = (rule: string, detail?: string) =>
		results.push({ rule, passed: true, detail });
	const fail = (rule: string, detail: string) =>
		results.push({ rule, passed: false, detail });

	const maxCostWei = computeMaxCost(candidate);
	const overheadWei = computeOverheadBound(candidate, overhead);
	const maxChargeWei = maxCostWei + feeWei + overheadWei;

	let reason: SponsorshipRefusalReason | undefined;
	let detail: string | undefined;
	/** First failure decides, but every rule still runs and is still recorded. */
	const refuse = (
		rule: string,
		why: SponsorshipRefusalReason,
		message: string,
	) => {
		fail(rule, message);
		if (!reason) {
			reason = why;
			detail = message;
		}
	};

	// 1. Is sponsorship on at all, and is the configuration usable?
	if (input.configUnparseable) {
		refuse(
			"sponsorship-enabled",
			"no-sponsorship-config",
			"the stored sponsorship configuration could not be parsed",
		);
	} else if (!config.enabled) {
		refuse(
			"sponsorship-enabled",
			"sponsorship-disabled",
			"sponsorship is switched off for this tenant",
		);
	} else if (config.allowlist.length === 0) {
		refuse(
			"sponsorship-enabled",
			"no-sponsorship-config",
			"no contracts are allow-listed",
		);
	} else {
		pass("sponsorship-enabled");
	}

	// 2. The operation must be for the session's own wallet.
	if (candidate.sender.toLowerCase() !== sessionWalletAddress.toLowerCase()) {
		refuse(
			"sender-binding",
			"not-your-wallet",
			`sender ${candidate.sender} is not this session's wallet ${sessionWalletAddress}`,
		);
	} else {
		pass("sender-binding");
	}

	// 3. Decode, or refuse. Never guess.
	const calls = decodeInnerCalls(candidate.callData);
	const classified = (calls ?? []).map((call) => ({
		call,
		kind: classifyCall(call, candidate.sender),
	}));
	if (calls === null) {
		refuse(
			"decodable-calls",
			"contract-not-allowed",
			"callData is not a decodable execute/executeBatch call",
		);
	} else if (calls.length === 0) {
		refuse(
			"decodable-calls",
			"contract-not-allowed",
			"the operation contains no calls",
		);
	} else {
		pass("decodable-calls", `${calls.length} inner call(s)`);
	}

	// 3b. Self-calls. A call from the wallet to itself is sponsored only as wallet management (see
	//     classifyCall). Any other self-call may run a payload these rules cannot check. The
	//     reason stays `contract-not-allowed`, the reason the wallet already knows, but the rule
	//     has its own name so the decision table says why.
	const refusedSelfCalls = classified.filter(
		({ kind }) => kind === "refused-self-call",
	);
	if (refusedSelfCalls.length > 0) {
		refuse(
			"self-calls",
			"contract-not-allowed",
			`a call from the wallet to itself is sponsored only to add or remove an owner (with no value), or as a plain value transfer; refused: ${refusedSelfCalls
				.map(
					({ call }) =>
						`${call.selector ?? "calldata with no selector"}${call.value > 0n ? ` with value ${call.value}` : ""}`,
				)
				.join(", ")}`,
		);
	} else {
		pass("self-calls");
	}

	// 4. Wallet management: a call from the wallet to itself that adds or removes an owner (see
	//    OWNER_MANAGEMENT_SELECTORS for why this is a list of allowed functions), or a plain value
	//    transfer to self (see classifyCall). Rule 3b refuses every other self-call, and it is
	//    excluded here so it can never gain the wallet-management cap or skip the allowlist.
	//
	//    These transactions are sponsored. A user acquiring a second device holds no native token
	//    and has no way to obtain one, so an unsponsored recovery path does not work for the users
	//    who need it. That is why the rule is the platform's and not an allowlist entry: a tenant
	//    that forgot to list something must not be able to break account recovery.
	const isWalletManagement = classified.some(
		({ kind }) => kind === "wallet-management",
	);
	const hasApplicationCalls = classified.some(
		({ kind }) => kind === "application",
	);

	const tenantCapWei = config.maxCostPerTxWei
		? BigInt(config.maxCostPerTxWei)
		: undefined;
	let capWei = tenantCapWei;
	let capSource: SponsorshipDecision["capSource"] =
		tenantCapWei === undefined ? undefined : "tenant";

	if (!isWalletManagement) {
		pass("wallet-management", "not a wallet-management operation");
	} else if (!walletManagementEnabled(config)) {
		// Only reachable when the tenant has explicitly switched it off — never by leaving something
		// out of a list, which is the whole point of the rule living here.
		refuse(
			"wallet-management",
			"wallet-management-not-sponsored",
			"this tenant has explicitly switched off sponsorship of wallet-management transactions",
		);
	} else {
		// The tenant may lower the platform cap and never raise it, so the lower of the two governs
		// even for a row written while the platform cap was higher.
		const tenantWmCap = config.walletManagement?.maxCostPerTxWei;
		const wmCapWei =
			tenantWmCap === undefined
				? input.walletManagementCapWei
				: min(BigInt(tenantWmCap), input.walletManagementCapWei);
		const wmCapSource: SponsorshipDecision["capSource"] =
			tenantWmCap !== undefined &&
			BigInt(tenantWmCap) <= input.walletManagementCapWei
				? "wallet-management-tenant"
				: "platform";

		if (
			hasApplicationCalls &&
			tenantCapWei !== undefined &&
			tenantCapWei < wmCapWei
		) {
			// A mixed batch is one charge and the chain cannot split it, so the tighter cap governs.
			capWei = tenantCapWei;
			capSource = "tenant";
			pass(
				"wallet-management",
				`sponsored; mixed batch, so the tenant's tighter cap of ${capWei} wei applies`,
			);
		} else {
			capWei = wmCapWei;
			capSource = wmCapSource;
			pass(
				"wallet-management",
				`sponsored under the ${wmCapSource === "platform" ? "platform" : "tenant's lowered"} cap of ${capWei} wei`,
			);
		}
	}

	// 5 & 6. Contract and function allowlists. A batch is all-or-nothing: partial sponsorship is
	//        not something the chain can express, so one disallowed call refuses the whole
	//        operation.
	const byContract = new Map(
		config.allowlist.map((entry) => [entry.contract, entry.functions]),
	);
	const contractFailures: string[] = [];
	const functionFailures: string[] = [];

	for (const { call, kind } of classified) {
		// Wallet management is governed by rule 4, not by the allowlist — a tenant should not have
		// to allow-list its users' own wallet addresses, which it cannot know in advance. A refused
		// self-call is not skipped, so it also fails here if rule 3b is ever changed.
		if (kind === "wallet-management") continue;

		const allowed = byContract.get(call.target.toLowerCase() as Address);
		if (!allowed) {
			contractFailures.push(call.target);
			continue;
		}
		if (allowed === "all") continue;
		if (call.selector === null) {
			functionFailures.push(
				`${call.target}: a bare value transfer with no selector`,
			);
			continue;
		}
		if (!allowed.includes(call.selector)) {
			functionFailures.push(`${call.target}.${call.selector}`);
		}
	}

	if (contractFailures.length > 0) {
		refuse(
			"contract-allowlist",
			"contract-not-allowed",
			`not allow-listed: ${contractFailures.join(", ")}`,
		);
	} else {
		pass("contract-allowlist");
	}

	if (functionFailures.length > 0) {
		refuse(
			"function-allowlist",
			"function-not-allowed",
			`function not permitted: ${functionFailures.join(", ")}`,
		);
	} else {
		pass("function-allowlist");
	}

	// 7. The per-transaction cost cap, applied to the *whole* charge. Capping gas alone would let
	//    the fee and the overhead push the real cost past what the tenant agreed to.
	if (capWei === undefined) {
		refuse(
			"max-cost",
			"no-sponsorship-config",
			"no per-transaction cost cap is configured",
		);
	} else if (maxChargeWei > capWei) {
		refuse(
			"max-cost",
			"cost-exceeds-cap",
			`maximum charge ${maxChargeWei} wei (gas ${maxCostWei} + fee ${feeWei} + overhead ${overheadWei}) exceeds the ` +
				`${capSource ?? "tenant"} cap of ${capWei} wei`,
		);
	} else {
		pass(
			"max-cost",
			`${maxChargeWei} wei of a ${capWei} wei ${capSource ?? "tenant"} cap`,
		);
	}

	// 8. Available balance. A deficit is money the pooled deposit already absorbed on this
	//    tenant's behalf, so it stops further authorisation until the tenant funds.
	if (balance.deficitWei > 0n) {
		refuse(
			"sufficient-balance",
			"tenant-in-deficit",
			`an outstanding deficit of ${balance.deficitWei} wei must be funded first`,
		);
	} else {
		const availableWei = balance.balanceWei - balance.reservedWei;
		if (availableWei < maxChargeWei) {
			refuse(
				"sufficient-balance",
				"insufficient-balance",
				`available ${availableWei} wei (balance ${balance.balanceWei} − reserved ${balance.reservedWei}) cannot cover ${maxChargeWei} wei`,
			);
		} else {
			pass("sufficient-balance", `${availableWei} wei available`);
		}
	}

	return {
		allowed: reason === undefined,
		results,
		reason,
		detail,
		maxChargeWei,
		feeWei,
		overheadWei,
		capWei,
		capSource,
		isWalletManagement,
	};
}

function min(a: bigint, b: bigint): bigint {
	return a < b ? a : b;
}
