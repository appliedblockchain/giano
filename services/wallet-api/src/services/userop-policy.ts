import { gianoSmartWalletAbi } from "@appliedblockchain/giano-contracts";
import type { Address, Hex } from "viem";
import { decodeFunctionData } from "viem";

/**
 * Policy pipeline for relayed user operations. Every rule produces an audit entry;
 * the full list is persisted on the userop_log row whether accepted or rejected.
 *
 * What it protects, and the threat behind each rule, is written down in the README's "Relay
 * policy" section. Add a line there with every new rule.
 */

export type PolicyRuleResult = {
	rule: string;
	passed: boolean;
	detail?: string;
};

export type PolicyDecision = {
	allowed: boolean;
	results: PolicyRuleResult[];
	/** First failing rule's human-readable reason. */
	rejectReason?: string;
};

/**
 * Extracts the tenant id a sponsored operation names, from the paymaster authorisation header.
 *
 * `paymasterData` is everything after the EntryPoint's 20+16+16 prefix; the Giano layout is
 * `version(1) ‖ tenantId(16) ‖ …`. Anything that is not that layout returns null — this is a
 * cross-check, not a parser, and a paymaster with a different data format is not a mismatch.
 */
export function decodeSponsoredTenantId(
	paymasterData: Hex | undefined,
): Hex | null {
	if (!paymasterData || paymasterData.length < 2 + 2 + 32) return null;
	const body = paymasterData.slice(2);
	if (body.slice(0, 2) !== "01") return null;
	return `0x${body.slice(2, 34)}`;
}

export type PolicyConfig = {
	maxCallGas: bigint;
	maxVerificationGas: bigint;
	maxPreVerificationGas: bigint;
	maxPaymasterVerificationGas: bigint;
	maxPaymasterPostOpGas: bigint;
	maxFeePerGas: bigint;
	maxPriorityFeePerGas: bigint;
	/** lowercase addresses; empty = no restriction (an `"any"` choice resolves to this) */
	allowedTargets: string[];
	/** lowercase addresses; empty = no restriction */
	allowedPaymasters: string[];
	/**
	 * The tenant this session belongs to, as the 16-byte id the paymaster bills. When present, an
	 * operation sponsored by Giano's paymaster must name it.
	 */
	sponsorshipTenantId?: Hex;
	/**
	 * Set when the chain's relay policy has a problem: its stored row does not parse, or (production)
	 * a field nothing decides. The `chain-policy` rule then refuses the operation (chain-policy.ts).
	 */
	chainPolicyError?: string;
	/**
	 * Set when the tenant's stored policy could not be parsed. The `tenant-policy` rule then refuses
	 * the operation: a broken policy must never loosen the relay to the deployment defaults.
	 */
	tenantPolicyError?: string;
};

export type PolicyUserOp = {
	sender: Address;
	callData: Hex;
	callGasLimit: bigint;
	verificationGasLimit: bigint;
	preVerificationGas: bigint;
	maxFeePerGas: bigint;
	maxPriorityFeePerGas: bigint;
	paymaster?: Address;
	paymasterVerificationGasLimit?: bigint;
	paymasterPostOpGasLimit?: bigint;
	paymasterData?: Hex;
	// `factory`/`factoryData` are deliberately absent: sender binding and the EntryPoint's own
	// checks leave a mismatched factory nothing to do (README, "Relay policy").
};

/** Decodes execute/executeBatch calldata into target addresses. Unknown selectors → null. */
export function decodeCallTargets(callData: Hex): Address[] | null {
	try {
		const decoded = decodeFunctionData({
			abi: gianoSmartWalletAbi,
			data: callData,
		});
		if (decoded.functionName === "execute") {
			return [decoded.args[0] as Address];
		}
		if (decoded.functionName === "executeBatch") {
			return (decoded.args[0] as readonly { target: Address }[]).map(
				(call) => call.target,
			);
		}
		return null;
	} catch {
		return null;
	}
}

export function evaluatePolicy(
	userOp: PolicyUserOp,
	sessionWalletAddress: string,
	config: PolicyConfig,
): PolicyDecision {
	const results: PolicyRuleResult[] = [];
	const fail = (rule: string, detail: string) =>
		results.push({ rule, passed: false, detail });
	const pass = (rule: string, detail?: string) =>
		results.push({ rule, passed: true, detail });

	// 0. the chain's policy must be decided and readable. If it is not, the caps and allowlists below
	//    are fallbacks nobody chose, so the operation is refused rather than checked against them.
	if (config.chainPolicyError !== undefined) {
		fail("chain-policy", config.chainPolicyError);
	} else {
		pass("chain-policy");
	}

	// 0b. the tenant's own policy must be readable. If it is not, no cap or allowlist below is the
	//    tenant's, so the operation is refused rather than checked against the deployment defaults.
	if (config.tenantPolicyError !== undefined) {
		fail(
			"tenant-policy",
			`the tenant's stored policy is invalid, so its operations are refused: ${config.tenantPolicyError}`,
		);
	} else {
		pass("tenant-policy");
	}

	// 1. sender binding: the op must be from the session credential's wallet
	if (userOp.sender.toLowerCase() !== sessionWalletAddress.toLowerCase()) {
		fail(
			"sender-binding",
			`sender ${userOp.sender} does not match session wallet ${sessionWalletAddress}`,
		);
	} else {
		pass("sender-binding");
	}

	// 2. gas caps
	if (userOp.callGasLimit > config.maxCallGas) {
		fail(
			"call-gas-cap",
			`callGasLimit ${userOp.callGasLimit} > cap ${config.maxCallGas}`,
		);
	} else {
		pass("call-gas-cap");
	}
	if (userOp.verificationGasLimit > config.maxVerificationGas) {
		fail(
			"verification-gas-cap",
			`verificationGasLimit ${userOp.verificationGasLimit} > cap ${config.maxVerificationGas}`,
		);
	} else {
		pass("verification-gas-cap");
	}

	if (userOp.preVerificationGas > config.maxPreVerificationGas) {
		fail(
			"pre-verification-gas-cap",
			`preVerificationGas ${userOp.preVerificationGas} > cap ${config.maxPreVerificationGas}`,
		);
	} else {
		pass("pre-verification-gas-cap");
	}
	const paymasterGasCap = (
		rule: string,
		field: string,
		value: bigint | undefined,
		cap: bigint,
	) => {
		if (!userOp.paymaster) pass(rule, "no paymaster in op");
		else if ((value ?? 0n) > cap) fail(rule, `${field} ${value} > cap ${cap}`);
		else pass(rule);
	};
	paymasterGasCap(
		"paymaster-verification-gas-cap",
		"paymasterVerificationGasLimit",
		userOp.paymasterVerificationGasLimit,
		config.maxPaymasterVerificationGas,
	);
	paymasterGasCap(
		"paymaster-post-op-gas-cap",
		"paymasterPostOpGasLimit",
		userOp.paymasterPostOpGasLimit,
		config.maxPaymasterPostOpGas,
	);

	// 3. fee caps
	if (userOp.maxFeePerGas > config.maxFeePerGas) {
		fail(
			"max-fee-cap",
			`maxFeePerGas ${userOp.maxFeePerGas} > cap ${config.maxFeePerGas}`,
		);
	} else {
		pass("max-fee-cap");
	}
	if (userOp.maxPriorityFeePerGas > config.maxPriorityFeePerGas) {
		fail(
			"priority-fee-cap",
			`maxPriorityFeePerGas ${userOp.maxPriorityFeePerGas} > cap ${config.maxPriorityFeePerGas}`,
		);
	} else {
		pass("priority-fee-cap");
	}

	// 4. target allowlist (only when configured)
	if (config.allowedTargets.length > 0) {
		const targets = decodeCallTargets(userOp.callData);
		if (targets === null) {
			fail(
				"target-allowlist",
				"callData is not a decodable execute/executeBatch call",
			);
		} else {
			const disallowed = targets.filter(
				(t) => !config.allowedTargets.includes(t.toLowerCase()),
			);
			if (disallowed.length > 0) {
				fail(
					"target-allowlist",
					`targets not allowed: ${disallowed.join(", ")}`,
				);
			} else {
				pass("target-allowlist", `targets: ${targets.join(", ")}`);
			}
		}
	} else {
		pass("target-allowlist", "no restriction configured");
	}

	// 5. paymaster allowlist (only when configured)
	if (config.allowedPaymasters.length > 0) {
		if (!userOp.paymaster) {
			pass("paymaster-allowlist", "no paymaster in op");
		} else if (
			!config.allowedPaymasters.includes(userOp.paymaster.toLowerCase())
		) {
			fail("paymaster-allowlist", `paymaster not allowed: ${userOp.paymaster}`);
		} else {
			pass("paymaster-allowlist");
		}
	} else {
		pass("paymaster-allowlist", "no restriction configured");
	}

	// 6. Sponsored-tenant cross-check. The paymaster already enforces this on chain — the tenant is
	//    inside the authorisation signature — so this is defence in depth: it catches a service bug
	//    or a tampered operation before the bundler sees it, and it costs a slice of bytes.
	const sponsoredTenant = decodeSponsoredTenantId(userOp.paymasterData);
	if (!config.sponsorshipTenantId || !sponsoredTenant) {
		pass(
			"sponsored-tenant-match",
			sponsoredTenant
				? "no session tenant to compare against"
				: "not a Giano-sponsored operation",
		);
	} else if (
		sponsoredTenant.toLowerCase() !== config.sponsorshipTenantId.toLowerCase()
	) {
		fail(
			"sponsored-tenant-match",
			`operation bills tenant ${sponsoredTenant}, session belongs to ${config.sponsorshipTenantId}`,
		);
	} else {
		pass("sponsored-tenant-match");
	}

	const firstFailure = results.find((r) => !r.passed);
	return {
		allowed: !firstFailure,
		results,
		rejectReason: firstFailure
			? `${firstFailure.rule}: ${firstFailure.detail}`
			: undefined,
	};
}
