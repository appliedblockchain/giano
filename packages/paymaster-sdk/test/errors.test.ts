import {
	gianoPaymasterAbi,
	gianoTimelockAbi,
} from "@appliedblockchain/giano-contracts";
import {
	ContractFunctionExecutionError,
	ContractFunctionRevertedError,
	encodeErrorResult,
	parseEther,
} from "viem";
import { describe, expect, it } from "vitest";
import {
	ExceedsTreasuryError,
	InsufficientTenantBalanceError,
	MissingRoleError,
	NotWithdrawAddressError,
	PaymasterPausedError,
	PaymasterRevertError,
	TenantAlreadyRegisteredError,
	TenantInDeficitError,
	TimelockOperationStateError,
	translateContractError,
	UnknownTenantError,
} from "../src/errors";
import { PAYMASTER_ROLES, roleName } from "../src/roles";

const ACCOUNT = "0x1111111111111111111111111111111111111111" as const;
const TENANT = "0x3f2504e04f8911d39a0c0305e82c3301" as const;

/**
 * Builds the failure viem actually produces for a reverted simulation: a
 * `ContractFunctionExecutionError` whose cause chain contains a `ContractFunctionRevertedError`
 * carrying the ABI-decoded custom error. Constructing it from real encoded revert data (rather
 * than hand-shaping the decoded object) keeps the test honest about the decoding step too.
 */
function revert(errorName: string, args: readonly unknown[]) {
	const data = encodeErrorResult({
		abi: gianoPaymasterAbi,
		errorName,
		args,
	} as never);
	const reverted = new ContractFunctionRevertedError({
		abi: gianoPaymasterAbi,
		data,
		functionName: "x",
	});
	return new ContractFunctionExecutionError(reverted, {
		abi: gianoPaymasterAbi,
		functionName: "x",
		args: [],
	});
}

const translate = (errorName: string, args: readonly unknown[]) =>
	translateContractError(revert(errorName, args), {
		operation: "do the thing",
		account: ACCOUNT,
		lookupRoleName: (role) => roleName(role),
	});

describe("translateContractError", () => {
	it("names the missing role rather than reporting a bare hash", () => {
		const error = translate("AccessControlUnauthorizedAccount", [
			ACCOUNT,
			PAYMASTER_ROLES.FEE_COLLECTOR_ROLE,
		]);

		expect(error).toBeInstanceOf(MissingRoleError);
		const missing = error as MissingRoleError;
		expect(missing.roleName).toBe("FEE_COLLECTOR_ROLE");
		expect(missing.account).toBe(ACCOUNT);
		expect(missing.message).toContain("FEE_COLLECTOR_ROLE");
		expect(missing.message).toContain("do the thing");
	});

	it("explains that no role can reach a tenant balance", () => {
		const error = translate("NotWithdrawAddress", [TENANT, ACCOUNT]);

		expect(error).toBeInstanceOf(NotWithdrawAddressError);
		expect((error as Error).message).toMatch(
			/no role defined by the paymaster can reach tenant funds/i,
		);
	});

	it("translates an unknown tenant and says how to fix it", () => {
		const error = translate("UnknownTenant", [TENANT]);

		expect(error).toBeInstanceOf(UnknownTenantError);
		expect((error as Error).message).toMatch(/TENANT_ADMIN_ROLE/);
	});

	it("translates a duplicate registration", () => {
		expect(translate("TenantAlreadyRegistered", [TENANT])).toBeInstanceOf(
			TenantAlreadyRegisteredError,
		);
	});

	it("carries the deficit amount, and says funding clears it", () => {
		const error = translate("TenantInDeficit", [TENANT, parseEther("0.25")]);

		expect(error).toBeInstanceOf(TenantInDeficitError);
		expect((error as TenantInDeficitError).deficitWei).toBe(parseEther("0.25"));
		expect((error as Error).message).toContain("0.25");
	});

	it("carries both sides of an insufficient balance", () => {
		const error = translate("InsufficientTenantBalance", [
			TENANT,
			parseEther("2"),
			parseEther("1"),
		]);

		expect(error).toBeInstanceOf(InsufficientTenantBalanceError);
		expect((error as InsufficientTenantBalanceError).requiredWei).toBe(
			parseEther("2"),
		);
		expect((error as InsufficientTenantBalanceError).availableWei).toBe(
			parseEther("1"),
		);
	});

	it("explains why the treasury withdrawal cap exists", () => {
		const error = translate("ExceedsTreasury", [
			parseEther("5"),
			parseEther("1"),
		]);

		expect(error).toBeInstanceOf(ExceedsTreasuryError);
		expect((error as Error).message).toMatch(/would reach tenant funds/i);
	});

	it.each(["PaymasterPaused", "EnforcedPause"])(
		"maps %s to a paused error that mentions withdrawals still work",
		(name) => {
			const error = translate(name, []);

			expect(error).toBeInstanceOf(PaymasterPausedError);
			expect((error as Error).message).toMatch(/withdrawals still work/i);
		},
	);

	it("falls back to a named revert for errors it has no dedicated class for", () => {
		const error = translate("ZeroAmount", []);

		expect(error).toBeInstanceOf(PaymasterRevertError);
		expect((error as PaymasterRevertError).errorName).toBe("ZeroAmount");
	});

	// Losing a transport failure behind a vaguer message would make real outages harder to
	// diagnose, so anything that is not a decoded revert has to come back untouched.
	it("returns a non-contract error unchanged", () => {
		const network = new Error("socket hang up");

		expect(translateContractError(network, { operation: "do the thing" })).toBe(
			network,
		);
	});
});

describe("timelocked roles and timelock reverts (G9)", () => {
	it("tells the operator a timelocked role is proposed through the timelock, not granted", () => {
		const error = translate("AccessControlUnauthorizedAccount", [
			ACCOUNT,
			PAYMASTER_ROLES.WITHDRAW_ADDRESS_ADMIN_ROLE,
		]) as MissingRoleError;

		expect(error).toBeInstanceOf(MissingRoleError);
		expect(error.timelocked).toBe(true);
		expect(error.message).toMatch(
			/WITHDRAW_ADDRESS_ADMIN_ROLE is timelocked: .*propose the call through the timelock/,
		);
	});

	it("keeps the plain grant advice for a role that acts immediately", () => {
		const error = translate("AccessControlUnauthorizedAccount", [
			ACCOUNT,
			PAYMASTER_ROLES.TENANT_ADMIN_ROLE,
		]) as MissingRoleError;

		expect(error.timelocked).toBe(false);
		expect(error.message).toMatch(/granted by the ROLE_ADMIN holder/);
	});

	it("decodes the timelock's expected-state bitmap into words", () => {
		const id = `0x${"11".repeat(32)}` as const;
		// 1 << Ready: what execute demands.
		const expected = `0x${"0".repeat(63)}4` as const;
		const data = encodeErrorResult({
			abi: gianoTimelockAbi,
			errorName: "TimelockUnexpectedOperationState",
			args: [id, expected],
		});
		const error = translateContractError(
			new ContractFunctionExecutionError(
				new ContractFunctionRevertedError({
					abi: gianoTimelockAbi,
					data,
					functionName: "execute",
				}),
				{ abi: gianoTimelockAbi, functionName: "execute", args: [] },
			),
			{ operation: "execute timelock operation" },
		) as TimelockOperationStateError;

		expect(error).toBeInstanceOf(TimelockOperationStateError);
		expect(error.operationId).toBe(id);
		expect(error.expected).toEqual(["ready"]);
		expect(error.message).toMatch(/to be ready/);
	});
});
