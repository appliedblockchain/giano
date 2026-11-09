import {
	PAYMASTER_ROLES,
	TIMELOCK_ROLES,
	type TimelockOperation,
} from "@appliedblockchain/giano-paymaster-sdk";
import { describe, expect, it } from "vitest";
import { queuedChanges, queuedKeys } from "./queued";

const TENANT = `0x${"ab".repeat(32)}` as const;
const PAYMASTER = `0x${"11".repeat(20)}` as const;

function operation(
	state: TimelockOperation["state"],
	calls: {
		contract: "paymaster" | "timelock";
		functionName: string;
		args: unknown[];
	}[],
): TimelockOperation {
	return {
		id: `0x${state.padEnd(64, "0").replace(/[^0-9a-f]/g, "0")}`,
		predecessor: `0x${"00".repeat(32)}`,
		salt: `0x${"00".repeat(32)}`,
		state,
		readyAt: 1_800_000_000,
		complete: true,
		calls: calls.map((decoded) => ({
			target: PAYMASTER,
			value: 0n,
			data: "0x",
			decoded: { ...decoded, summary: decoded.functionName },
		})),
	};
}

describe("queuedChanges", () => {
	it("keys each call of a pending operation by what it changes", () => {
		const changes = queuedChanges([
			operation("waiting", [
				{
					contract: "paymaster",
					functionName: "setTenantFee",
					args: [TENANT, true, 1n],
				},
				{
					contract: "paymaster",
					functionName: "setTenantWithdrawAddress",
					args: [TENANT, PAYMASTER],
				},
				{ contract: "paymaster", functionName: "setDefaultFee", args: [1n] },
				{
					contract: "paymaster",
					functionName: "grantRole",
					args: [PAYMASTER_ROLES.FEE_ADMIN_ROLE, PAYMASTER],
				},
				{
					contract: "paymaster",
					functionName: "upgradeToAndCall",
					args: [PAYMASTER, "0x"],
				},
			]),
			operation("ready", [
				{ contract: "timelock", functionName: "updateDelay", args: [60n] },
				{
					contract: "timelock",
					functionName: "setFunctionDelay",
					args: [PAYMASTER, "0xABCDEF01", 60n],
				},
				{
					contract: "timelock",
					functionName: "revokeRole",
					args: [TIMELOCK_ROLES.PROPOSER_ROLE, PAYMASTER],
				},
			]),
		]);
		expect(changes.map((change) => change.key)).toEqual([
			queuedKeys.tenantFee(TENANT),
			queuedKeys.tenantWithdraw(TENANT),
			queuedKeys.defaultFee,
			queuedKeys.role("FEE_ADMIN_ROLE"),
			queuedKeys.implementation,
			queuedKeys.timelockDelay("min"),
			queuedKeys.timelockDelay("0xabcdef01"),
			queuedKeys.timelockRole("PROPOSER_ROLE"),
		]);
		expect(changes[0]).toMatchObject({
			state: "waiting",
			readyAt: 1_800_000_000,
		});
	});

	it("matches a tenant whatever the case of its id", () => {
		expect(
			queuedKeys.tenantFee(
				TENANT.toUpperCase().replace("0X", "0x") as `0x${string}`,
			),
		).toBe(queuedKeys.tenantFee(TENANT));
	});

	it("leaves out operations that are not pending, and calls it cannot place", () => {
		const done = operation("done", [
			{ contract: "paymaster", functionName: "setDefaultFee", args: [1n] },
		]);
		const unknown = operation("waiting", [
			{ contract: "paymaster", functionName: "pause", args: [] },
		]);
		const undecoded: TimelockOperation = {
			...unknown,
			calls: [{ target: PAYMASTER, value: 0n, data: "0x12345678" }],
		};
		expect(queuedChanges([done, unknown, undecoded])).toEqual([]);
	});
});
