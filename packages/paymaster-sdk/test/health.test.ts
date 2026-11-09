import { keccak256, parseEther, zeroAddress } from "viem";
import { describe, expect, it, vi } from "vitest";
import { assessHealth, type HealthTimelock } from "../src/health";
import { DEFAULT_ADMIN_ROLE, PAYMASTER_ROLES } from "../src/roles";
import type { PaymasterOverview, RoleHolders, TenantView } from "../src/types";

const TIMELOCK = "0x1111111111111111111111111111111111111111" as const;
const SIGNER = "0x2222222222222222222222222222222222222222" as const;
const IMPLEMENTATION = "0x4444444444444444444444444444444444444444" as const;
/** An address whose checksum has letters in both cases. */
const MIXED_CASE = "0xf274De14171Ab928A5Ec19928cE35FaD91a42B64" as const;
/** Stands in for the runtime code of a release; the real matching is the contracts package's. */
const V2_CODE = "0x6080600101" as const;

vi.mock("@appliedblockchain/giano-contracts", async (importOriginal) => {
	const actual =
		await importOriginal<typeof import("@appliedblockchain/giano-contracts")>();
	return {
		...actual,
		releaseOf: (contract: string, code: string) =>
			contract === "GianoPaymaster" && code === V2_CODE
				? {
						contract,
						release: "v2",
						size: 5,
						immutables: [],
						fingerprint: "0x00",
					}
				: undefined,
	};
});

function tenant(overrides: Partial<TenantView> = {}): TenantView {
	return {
		id: "0x3f2504e04f8911d39a0c0305e82c3301",
		uuid: "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
		registered: true,
		enabled: true,
		hasFeeOverride: false,
		withdrawAddress: TIMELOCK,
		balance: parseEther("1"),
		deficit: 0n,
		feeWeiOverride: 0n,
		effectiveFeeWei: parseEther("0.0001"),
		status: "active",
		...overrides,
	};
}

function roles(
	overrides: Partial<Record<string, readonly `0x${string}`[]>> = {},
): readonly RoleHolders[] {
	const holders = (name: string, fallback: readonly `0x${string}`[]) =>
		overrides[name] ?? fallback;
	return [
		{
			name: "DEFAULT_ADMIN_ROLE",
			role: DEFAULT_ADMIN_ROLE,
			holders: holders("DEFAULT_ADMIN_ROLE", []),
		},
		{
			name: "ROLE_ADMIN",
			role: PAYMASTER_ROLES.ROLE_ADMIN,
			holders: holders("ROLE_ADMIN", [TIMELOCK]),
		},
		{
			name: "UPGRADER_ROLE",
			role: PAYMASTER_ROLES.UPGRADER_ROLE,
			holders: holders("UPGRADER_ROLE", [TIMELOCK]),
		},
		{
			name: "FEE_ADMIN_ROLE",
			role: PAYMASTER_ROLES.FEE_ADMIN_ROLE,
			holders: holders("FEE_ADMIN_ROLE", [TIMELOCK]),
		},
		{
			name: "WITHDRAW_ADDRESS_ADMIN_ROLE",
			role: PAYMASTER_ROLES.WITHDRAW_ADDRESS_ADMIN_ROLE,
			holders: holders("WITHDRAW_ADDRESS_ADMIN_ROLE", [TIMELOCK]),
		},
	];
}

function overview(
	overrides: Partial<PaymasterOverview> = {},
): PaymasterOverview {
	const tenants = overrides.tenants ?? [tenant()];
	const tenantBalancesWei = tenants.reduce(
		(sum, current) => sum + current.balance,
		0n,
	);
	const treasuryWei = parseEther("0.01");
	const depositWei = parseEther("5");

	return {
		address: "0x3333333333333333333333333333333333333333",
		chainId: 31337,
		config: {
			entryPoint: "0x433709009B8330FDa32311DF1C2AFA402eD8D009",
			defaultFeeWei: parseEther("0.0001"),
			postOpGasAllowance: 40_000,
			penaltyBps: 1000,
			paused: false,
		},
		stake: {
			depositWei,
			stakeWei: parseEther("1"),
			staked: true,
			unstakeDelaySec: 86_400,
			withdrawTime: 0,
		},
		solvency: {
			tenantBalancesWei,
			treasuryWei,
			claimsWei: tenantBalancesWei + treasuryWei,
			depositWei,
			slackWei: depositWei - (tenantBalancesWei + treasuryWei),
			holds: true,
		},
		tenants,
		signers: [SIGNER],
		roles: roles(),
		...overrides,
	};
}

const check = (report: ReturnType<typeof assessHealth>, id: string) =>
	report.checks.find((candidate) => candidate.id === id);

describe("assessHealth", () => {
	it("passes a well-provisioned deployment, warning only that no timelock is configured", () => {
		const report = assessHealth(overview());

		expect(check(report, "solvency")?.level).toBe("ok");
		expect(check(report, "stake")?.level).toBe("ok");
		expect(check(report, "deposit")?.level).toBe("ok");
		expect(check(report, "signers")?.level).toBe("ok");
		expect(check(report, "no-superuser")?.level).toBe("ok");
		expect(check(report, "tenants-funded")?.level).toBe("ok");
		// Without a timelock the timelocked roles cannot be asserted: one warning, not one per holder.
		expect(check(report, "timelock")?.level).toBe("warn");
		expect(check(report, "timelock")?.detail).toContain(TIMELOCK);
		expect(check(report, "role-ROLE_ADMIN")).toBeUndefined();
		expect(
			report.checks.some((entry) =>
				/verify this is the timelock/.test(entry.detail),
			),
		).toBe(false);
		expect(report.level).toBe("warn");
	});

	it("fails a breached invariant, which is an insolvency rather than a warning", () => {
		const base = overview();
		const report = assessHealth({
			...base,
			solvency: {
				...base.solvency,
				claimsWei: parseEther("99"),
				slackWei: -parseEther("94"),
				holds: false,
			},
		});

		expect(check(report, "solvency")?.level).toBe("fail");
		expect(check(report, "solvency")?.remedy).toMatch(
			/Stop issuing sponsorships/i,
		);
		expect(report.level).toBe("fail");
	});

	it("fails an unstaked paymaster, because bundlers reject it outright", () => {
		const base = overview();
		const report = assessHealth({
			...base,
			stake: { ...base.stake, staked: false, stakeWei: 0n },
		});

		expect(check(report, "stake")?.level).toBe("fail");
		expect(check(report, "stake")?.remedy).toMatch(/STAKE_ADMIN_ROLE/);
	});

	it("fails a stake below the working minimum even when it is technically staked", () => {
		const base = overview();
		const report = assessHealth({
			...base,
			stake: { ...base.stake, staked: true, stakeWei: parseEther("0.05") },
		});

		expect(check(report, "stake")?.level).toBe("fail");
	});

	it("warns while the stake is unlocking, since that also stops bundlers", () => {
		const base = overview();
		const report = assessHealth({
			...base,
			stake: { ...base.stake, withdrawTime: 1_800_000_000 },
		});

		expect(check(report, "stake-unlocking")?.level).toBe("warn");
	});

	it("fails a low deposit", () => {
		const base = overview();
		const report = assessHealth({
			...base,
			solvency: { ...base.solvency, depositWei: parseEther("0.001") },
		});

		expect(check(report, "deposit")?.level).toBe("fail");
	});

	it("fails when no signing key is authorised, because nothing can be sponsored", () => {
		const report = assessHealth({ ...overview(), signers: [] });

		expect(check(report, "signers")?.level).toBe("fail");
		expect(report.level).toBe("fail");
	});

	it("fails when DEFAULT_ADMIN_ROLE is held — that is a superuser by another name", () => {
		const report = assessHealth({
			...overview(),
			roles: roles({ DEFAULT_ADMIN_ROLE: [TIMELOCK] }),
		});

		expect(check(report, "no-superuser")?.level).toBe("fail");
	});

	it.each([
		["none", [] as readonly `0x${string}`[]],
		["two", [TIMELOCK, SIGNER] as readonly `0x${string}`[]],
	])(
		"fails when ROLE_ADMIN has %s holders rather than exactly one",
		(_label, holders) => {
			const report = assessHealth({
				...overview(),
				roles: roles({ ROLE_ADMIN: holders }),
			});

			expect(check(report, "role-ROLE_ADMIN")?.level).toBe("fail");
		},
	);

	it("warns when paused, and says withdrawals still work", () => {
		const base = overview();
		const report = assessHealth({
			...base,
			config: { ...base.config, paused: true },
		});

		expect(check(report, "paused")?.level).toBe("warn");
		expect(check(report, "paused")?.remedy).toMatch(/Withdrawals still work/i);
	});

	it("fails a tenant in deficit and names it", () => {
		const report = assessHealth({
			...overview(),
			tenants: [tenant({ deficit: parseEther("0.5"), status: "in-deficit" })],
		});

		expect(check(report, "tenant-deficits")?.level).toBe("fail");
		expect(check(report, "tenant-deficits")?.detail).toContain(
			"3f2504e0-4f89-11d3-9a0c-0305e82c3301",
		);
	});

	it("fails when no tenant holds a balance — a deployment is not complete until one does", () => {
		const report = assessHealth({
			...overview(),
			tenants: [tenant({ balance: 0n, status: "unfunded" })],
		});

		expect(check(report, "tenants-funded")?.level).toBe("fail");
	});

	it("warns rather than fails when there are no tenants at all", () => {
		const base = overview({ tenants: [] });
		const report = assessHealth(base);

		expect(check(report, "tenants-funded")?.level).toBe("warn");
	});

	it("reports the worst level across every check", () => {
		const base = overview();
		const healthy = assessHealth(base);
		expect(healthy.level).toBe("warn");

		const broken = assessHealth({ ...base, signers: [] });
		expect(broken.level).toBe("fail");
	});
});

const DELAYS = {
	minDelay: 2 * 86_400,
	upgradeToAndCall: 7 * 86_400,
	grantRole: 7 * 86_400,
	revokeRole: 7 * 86_400,
	renounceRole: 7 * 86_400,
	setTenantWithdrawAddress: 3 * 86_400,
	setDefaultFee: 2 * 86_400,
	setTenantFee: 2 * 86_400,
};

const timelock = (overrides: Partial<HealthTimelock> = {}): HealthTimelock => ({
	address: TIMELOCK,
	delays: DELAYS,
	expected: DELAYS,
	...overrides,
});

describe("assessHealth with a timelock (B2)", () => {
	it("passes when the timelock alone holds every timelocked role, and asks to verify nothing", () => {
		const report = assessHealth(overview(), { timelock: timelock() });

		expect(check(report, "timelocked-roles")?.level).toBe("ok");
		expect(check(report, "timelock-delays")?.level).toBe("ok");
		expect(check(report, "timelock")).toBeUndefined();
		expect(report.checks.every((entry) => entry.level === "ok")).toBe(true);
		expect(report.level).toBe("ok");
	});

	it("names a key that kept several roles once, with its roles", () => {
		const report = assessHealth(
			{
				...overview(),
				roles: roles({
					ROLE_ADMIN: [TIMELOCK, SIGNER],
					UPGRADER_ROLE: [SIGNER],
				}),
			},
			{ timelock: timelock() },
		);

		expect(check(report, "timelocked-roles")?.detail).toBe(
			`${SIGNER} also holds ROLE_ADMIN, UPGRADER_ROLE; the timelock ${TIMELOCK} does not hold UPGRADER_ROLE`,
		);
	});

	it("fails an extra holder beside the timelock, and names it", () => {
		const report = assessHealth(
			{ ...overview(), roles: roles({ FEE_ADMIN_ROLE: [TIMELOCK, SIGNER] }) },
			{ timelock: timelock() },
		);

		expect(check(report, "timelocked-roles")?.level).toBe("fail");
		expect(check(report, "timelocked-roles")?.detail).toBe(
			`${SIGNER} also holds FEE_ADMIN_ROLE`,
		);
	});

	it("fails a timelocked role the timelock does not hold, naming the timelock checksummed", () => {
		const report = assessHealth(
			{ ...overview(), roles: roles({ UPGRADER_ROLE: [SIGNER] }) },
			{
				timelock: timelock({
					address: MIXED_CASE.toLowerCase() as `0x${string}`,
				}),
			},
		);

		expect(check(report, "timelocked-roles")?.detail).toContain(
			`the timelock ${MIXED_CASE} does not hold ROLE_ADMIN, UPGRADER_ROLE, FEE_ADMIN_ROLE, WITHDRAW_ADDRESS_ADMIN_ROLE`,
		);
	});

	it("fails a delay below the profile, naming it, what it is and what it should be", () => {
		const report = assessHealth(overview(), {
			timelock: timelock({
				delays: { ...DELAYS, upgradeToAndCall: 86_400 },
			}),
		});

		expect(check(report, "timelock-delays")?.level).toBe("fail");
		expect(check(report, "timelock-delays")?.detail).toContain(
			"upgradeToAndCall waits 1d, below the published 7d",
		);
	});

	it("fails a role change that waits less than what it could bypass, even without published values", () => {
		const report = assessHealth(overview(), {
			timelock: timelock({
				delays: { ...DELAYS, grantRole: 86_400, minDelay: 86_400 },
				expected: undefined,
			}),
		});

		expect(check(report, "timelock-delays")?.level).toBe("fail");
		expect(check(report, "timelock-delays")?.detail).toMatch(
			/grantRole waits 1d/,
		);
	});

	it("warns that the delays were not compared when there are no published values", () => {
		const report = assessHealth(overview(), {
			timelock: timelock({ expected: undefined }),
		});

		expect(check(report, "timelock-delays")?.level).toBe("warn");
	});
});

describe("assessHealth and the implementation (B2)", () => {
	it("passes code that is a release, and says which", () => {
		const report = assessHealth(overview(), {
			timelock: timelock(),
			implementation: { address: IMPLEMENTATION, code: V2_CODE },
		});

		expect(check(report, "implementation")?.level).toBe("ok");
		expect(check(report, "implementation")?.detail).toBe(
			`release v2 at ${IMPLEMENTATION}`,
		);
	});

	it("fails code that matches no release, giving the address and its codehash", () => {
		const code = "0x60806001ff" as const;
		const report = assessHealth(overview(), {
			implementation: { address: IMPLEMENTATION, code },
		});

		expect(check(report, "implementation")?.level).toBe("fail");
		expect(check(report, "implementation")?.detail).toBe(
			`${IMPLEMENTATION}, codehash ${keccak256(code)}`,
		);
	});

	it("fails an implementation with no code", () => {
		const report = assessHealth(overview(), {
			implementation: { address: IMPLEMENTATION, code: undefined },
		});

		expect(check(report, "implementation")?.detail).toBe(
			`no code at ${IMPLEMENTATION}`,
		);
	});

	it("fails a paymaster whose implementation slot is empty, saying it is not a proxy", () => {
		const report = assessHealth(overview(), {
			implementation: { address: zeroAddress, code: undefined },
		});

		expect(check(report, "implementation")?.level).toBe("fail");
		expect(check(report, "implementation")?.detail).toMatch(/not a UUPS proxy/);
	});
});
