import {
	roleName,
	type TimelockOperation,
	timelockRoleName,
} from "@appliedblockchain/giano-paymaster-sdk";
import type { Hex } from "viem";

/**
 * Where a pending timelock change will land, as a key a marker can ask for.
 *
 * - `default-fee`, `implementation`
 * - `tenant-fee:<tenant id>`, `tenant-withdraw:<tenant id>` — the id lowercased
 * - `role:<paymaster role name>`
 * - `timelock-delay:min`, `timelock-delay:<selector>`
 * - `timelock-role:<timelock role name>`
 */
export type QueuedKey = string;

/** One call of a waiting or ready operation, by what it changes. */
export type QueuedChange = {
	key: QueuedKey;
	operationId: Hex;
	state: "waiting" | "ready";
	/** Unix seconds it can execute from. */
	readyAt?: number;
	/** The SDK's sentence for the call, e.g. `set the default fee to 0.0001 ETH`. */
	summary: string;
};

export const queuedKeys = {
	defaultFee: "default-fee",
	implementation: "implementation",
	tenantFee: (tenantId: Hex) => `tenant-fee:${tenantId.toLowerCase()}`,
	tenantWithdraw: (tenantId: Hex) =>
		`tenant-withdraw:${tenantId.toLowerCase()}`,
	role: (name: string) => `role:${name}`,
	timelockDelay: (selector: Hex | "min") =>
		`timelock-delay:${selector === "min" ? "min" : selector.toLowerCase()}`,
	timelockRole: (name: string) => `timelock-role:${name}`,
} as const;

/**
 * The changes the pending operations will make, one per call the SDK could decode. An operation
 * that is done, cancelled or unknown is not pending; a call the SDK could not decode changes
 * nothing the console can point at, and is listed in the Timelock tab only.
 */
export function queuedChanges(
	operations: readonly TimelockOperation[],
): QueuedChange[] {
	const changes: QueuedChange[] = [];
	for (const operation of operations) {
		if (operation.state !== "waiting" && operation.state !== "ready") continue;
		for (const call of operation.calls) {
			if (!call.decoded) continue;
			const key = keyOf(
				call.decoded.contract,
				call.decoded.functionName,
				call.decoded.args,
			);
			if (!key) continue;
			changes.push({
				key,
				operationId: operation.id,
				state: operation.state,
				readyAt: operation.readyAt,
				summary: call.decoded.summary,
			});
		}
	}
	return changes;
}

function keyOf(
	contract: "paymaster" | "timelock",
	functionName: string,
	args: readonly unknown[],
): QueuedKey | undefined {
	if (contract === "timelock") {
		switch (functionName) {
			case "updateDelay":
				return queuedKeys.timelockDelay("min");
			case "setFunctionDelay":
				return queuedKeys.timelockDelay(args[1] as Hex);
			case "grantRole":
			case "revokeRole":
			case "renounceRole": {
				const name = timelockRoleName(args[0] as Hex);
				return name && queuedKeys.timelockRole(name);
			}
		}
		return undefined;
	}
	switch (functionName) {
		case "setDefaultFee":
			return queuedKeys.defaultFee;
		case "upgradeToAndCall":
			return queuedKeys.implementation;
		case "setTenantFee":
			return queuedKeys.tenantFee(args[0] as Hex);
		case "setTenantWithdrawAddress":
			return queuedKeys.tenantWithdraw(args[0] as Hex);
		case "grantRole":
		case "revokeRole":
		case "renounceRole": {
			const name = roleName(args[0] as Hex);
			return name && queuedKeys.role(name);
		}
	}
	return undefined;
}
