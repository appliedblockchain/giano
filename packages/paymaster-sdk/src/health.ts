import {
	type DelayShortfall,
	delayPolicyProblems,
	delayShortfalls,
	formatDuration,
	RELEASE_FINGERPRINTS,
	releaseOf,
	TIMELOCKED_FUNCTION_NAMES,
	TIMELOCKED_ROLES,
	type TimelockDelays,
	type TimelockedRoleProblem,
	timelockedRoleProblems,
} from "@appliedblockchain/giano-contracts";
import {
	type Address,
	formatEther,
	getAddress,
	type Hex,
	keccak256,
	zeroAddress,
} from "viem";
import type {
	HealthCheck,
	HealthLevel,
	HealthReport,
	PaymasterOverview,
} from "./types";

/**
 * Deployment health.
 *
 * The thresholds and verdicts are deliberately the same ones `giano-doctor` applies, so a panel
 * and the CI gate cannot disagree about whether a deployment is usable. They are pure functions of
 * an overview: no RPC here, which means a UI can re-evaluate them against data it already has, and
 * a test can drive every branch without a chain.
 *
 * What an overview cannot say comes in a {@link HealthContext}: the timelock the paymaster is
 * governed by, and the code at its implementation (B2).
 */

/** The paymaster's timelock, as read from the chain, and what its delays are meant to be. */
export type HealthTimelock = {
	address: Address;
	/** What the timelock enforces: `minDelay`, and each function's effective delay. */
	delays: TimelockDelays;
	/**
	 * The published delays, from the deployment's profile. Without them the delays are checked only
	 * against each other (a role change waits as long as what it could bypass). A name left out has
	 * no published value: the report warns that it was not compared, as `giano-doctor` does.
	 */
	expected?: Partial<TimelockDelays>;
};

/** What `assessHealth` checks beyond the overview, when the caller has it. */
export type HealthContext = {
	/** Without one, the report warns that no timelock is configured. */
	timelock?: HealthTimelock;
	/** The runtime code at the implementation, matched to a contracts release. */
	implementation?: { address: Address; code: Hex | undefined };
};

/** Below this, sponsored operations start failing in ways that look like client bugs. */
export const LOW_DEPOSIT_WEI = 20_000_000_000_000_000n; // 0.02 ETH

/** A validating paymaster needs a stake before bundlers will accept its operations at all. */
export const MIN_STAKE_WEI = 100_000_000_000_000_000n; // 0.1 ETH

const worst = (levels: readonly HealthLevel[]): HealthLevel =>
	levels.includes("fail") ? "fail" : levels.includes("warn") ? "warn" : "ok";

export function assessHealth(
	overview: PaymasterOverview,
	context: HealthContext = {},
): HealthReport {
	const checks: HealthCheck[] = [];
	const { config, stake, solvency, tenants, signers, roles } = overview;

	// --- solvency: the property everything else rests on ----------------------------------------
	checks.push(
		solvency.holds
			? {
					id: "solvency",
					level: "ok",
					label: "accounting invariant (Σ balances + treasury ≤ deposit)",
					detail: `${formatEther(solvency.claimsWei)} ≤ ${formatEther(solvency.depositWei)} ETH, ${formatEther(solvency.slackWei)} ETH unattributed slack`,
				}
			: {
					id: "solvency",
					level: "fail",
					label: "accounting invariant breached",
					detail: `claims ${formatEther(solvency.claimsWei)} ETH exceed the deposit ${formatEther(solvency.depositWei)} ETH`,
					remedy:
						"This is an insolvency. Stop issuing sponsorships and investigate before anything else.",
				},
	);

	// --- stake and deposit ----------------------------------------------------------------------
	checks.push(
		stake.staked && stake.stakeWei >= MIN_STAKE_WEI
			? {
					id: "stake",
					level: "ok",
					label: "paymaster staked",
					detail: `${formatEther(stake.stakeWei)} ETH`,
				}
			: {
					id: "stake",
					level: "fail",
					label: "paymaster stake",
					detail: stake.staked
						? `${formatEther(stake.stakeWei)} ETH, below the ${formatEther(MIN_STAKE_WEI)} ETH minimum`
						: "not staked",
					remedy:
						"Bundlers reject an unstaked validating paymaster, which reads as a client bug. Call addStake (STAKE_ADMIN_ROLE).",
				},
	);

	checks.push(
		solvency.depositWei >= LOW_DEPOSIT_WEI
			? {
					id: "deposit",
					level: "ok",
					label: "EntryPoint deposit",
					detail: `${formatEther(solvency.depositWei)} ETH`,
				}
			: {
					id: "deposit",
					level: "fail",
					label: "EntryPoint deposit",
					detail: `${formatEther(solvency.depositWei)} ETH, below the ${formatEther(LOW_DEPOSIT_WEI)} ETH working minimum`,
					remedy:
						"Fund a tenant — depositFor is the only way funds enter, and it credits the deposit too.",
				},
	);

	if (stake.withdrawTime > 0) {
		checks.push({
			id: "stake-unlocking",
			level: "warn",
			label: "stake is unlocking",
			detail: `withdrawable from unix time ${stake.withdrawTime}`,
			remedy:
				"An unlocked stake stops bundlers accepting operations. Re-stake unless this is a deliberate wind-down.",
		});
	}

	// --- signing keys ---------------------------------------------------------------------------
	checks.push(
		signers.length > 0
			? {
					id: "signers",
					level: "ok",
					label: "sponsorship signing keys",
					detail: signers.join(", "),
				}
			: {
					id: "signers",
					level: "fail",
					label: "sponsorship signing keys",
					detail: "none authorised",
					remedy:
						"Nothing can be authorised without one. Call addSigner (SIGNER_ADMIN_ROLE).",
				},
	);

	// --- role topology --------------------------------------------------------------------------
	const defaultAdmin = roles.find(
		(entry) => entry.name === "DEFAULT_ADMIN_ROLE",
	);
	checks.push(
		(defaultAdmin?.holders.length ?? 0) === 0
			? {
					id: "no-superuser",
					level: "ok",
					label: "no DEFAULT_ADMIN_ROLE holder",
					detail: "there is no superuser",
				}
			: {
					id: "no-superuser",
					level: "fail",
					label: "DEFAULT_ADMIN_ROLE is held",
					detail: `${defaultAdmin?.holders.join(", ")} — this is a superuser by another name`,
					remedy:
						"Revoke it. The design grants every power through its own named role instead.",
				},
	);

	checks.push(...timelockChecks(overview, context.timelock));
	if (context.implementation)
		checks.push(implementationCheck(context.implementation));

	// --- operational state ----------------------------------------------------------------------
	checks.push(
		config.paused
			? {
					id: "paused",
					level: "warn",
					label: "accepting new sponsorships",
					detail: "PAUSED",
					remedy:
						"Withdrawals still work. Unpause when the incident that motivated it is closed (PAUSER_ROLE).",
				}
			: {
					id: "paused",
					level: "ok",
					label: "accepting new sponsorships",
					detail: "not paused",
				},
	);

	// --- tenants --------------------------------------------------------------------------------
	const inDeficit = tenants.filter((tenant) => tenant.deficit > 0n);
	if (inDeficit.length > 0) {
		checks.push({
			id: "tenant-deficits",
			level: "fail",
			label: `${inDeficit.length} tenant(s) in deficit`,
			detail: inDeficit
				.map(
					(tenant) => `${tenant.uuid} owes ${formatEther(tenant.deficit)} ETH`,
				)
				.join("; "),
			remedy:
				"A tenant in deficit cannot transact. Funding it clears the deficit first, then credits the remainder.",
		});
	}

	const funded = tenants.filter((tenant) => tenant.balance > 0n);
	if (tenants.length === 0) {
		checks.push({
			id: "tenants-funded",
			level: "warn",
			label: "registered tenants",
			detail: "none",
			remedy:
				"Register one with registerTenant (TENANT_ADMIN_ROLE) before expecting sponsorship to work.",
		});
	} else {
		checks.push(
			funded.length > 0
				? {
						id: "tenants-funded",
						level: "ok",
						label: "funded tenants",
						detail: `${funded.length} of ${tenants.length}, ${formatEther(solvency.tenantBalancesWei)} ETH total`,
					}
				: {
						id: "tenants-funded",
						level: "fail",
						label: "funded tenants",
						detail: `none of ${tenants.length}`,
						remedy:
							"A deployment is not complete until at least one tenant holds a balance.",
					},
		);
	}

	return { level: worst(checks.map((check) => check.level)), checks };
}

const holdersOf = (overview: PaymasterOverview, name: string) =>
	overview.roles.find((entry) => entry.name === name)?.holders ?? [];

/**
 * The timelocked roles and the delays (G9 R4, B2): the same judgement as `giano-doctor chain`, from
 * the contracts package's `timelockedRoleProblems` and `delayShortfalls`.
 */
function timelockChecks(
	overview: PaymasterOverview,
	timelock: HealthTimelock | undefined,
): HealthCheck[] {
	if (!timelock) {
		const checks: HealthCheck[] = [];
		// Without a timelock, the two roles that govern the rest must still rest with one holder.
		for (const name of ["ROLE_ADMIN", "UPGRADER_ROLE"] as const) {
			const holders = holdersOf(overview, name);
			if (holders.length !== 1)
				checks.push({
					id: `role-${name}`,
					level: "fail",
					label: `${name} holders`,
					detail: `${holders.length} holder(s)${holders.length > 0 ? `: ${holders.join(", ")}` : ""} — expected exactly one`,
					remedy:
						"Both roles should rest with a single timelock. More than one holder widens the blast radius; none makes the contract unmaintainable.",
				});
		}
		const held = [
			...new Set(TIMELOCKED_ROLES.flatMap((role) => holdersOf(overview, role))),
		];
		checks.push({
			id: "timelock",
			level: "warn",
			label: "no timelock configured",
			detail: `the timelocked roles (${TIMELOCKED_ROLES.join(", ")}) are held by ${held.join(", ") || "nobody"}, and neither they nor the delays are checked`,
			remedy:
				"Configure the paymaster's timelock so these are checked. On a chain that holds real money, a key holding these roles can change fees, withdrawal addresses and the code with one signature.",
		});
		return checks;
	}

	const { delays, expected } = timelock;
	// Shown as every holder is, checksummed: configuration may spell it in lowercase.
	const address = getAddress(timelock.address);
	const problems = timelockedRoleProblems(
		Object.fromEntries(
			TIMELOCKED_ROLES.map((role) => [role, holdersOf(overview, role)]),
		),
		address,
	);
	const shortfalls = expected ? delayShortfalls(delays, expected) : [];
	const policy = delayPolicyProblems(delays);
	// A delay with no published value is not "at or above" it: name each one, as the doctor does.
	const uncompared = expected
		? (["minDelay", ...TIMELOCKED_FUNCTION_NAMES] as const).filter(
				(name) => expected[name] === undefined,
			)
		: [];
	return [
		problems.length === 0
			? {
					id: "timelocked-roles",
					level: "ok",
					label: "timelocked roles held by the timelock alone",
					detail: `${TIMELOCKED_ROLES.join(", ")}: ${address}`,
				}
			: {
					id: "timelocked-roles",
					level: "fail",
					label: "timelocked roles held outside the timelock",
					detail: describeRoleProblems(problems, address),
					remedy:
						"Any other holder can make a timelocked change without waiting. Revoke it, through the timelock (ROLE_ADMIN).",
				},
		delaysCheck(delays, expected, shortfalls, policy, uncompared),
	];
}

function delaysCheck(
	delays: TimelockDelays,
	expected: Partial<TimelockDelays> | undefined,
	shortfalls: readonly DelayShortfall[],
	policy: readonly string[],
	uncompared: readonly string[],
): HealthCheck {
	const summary = `minimum ${formatDuration(delays.minDelay)}, upgrades ${formatDuration(delays.upgradeToAndCall)}`;
	if (shortfalls.length > 0 || policy.length > 0)
		return {
			id: "timelock-delays",
			level: "fail",
			label: "timelock delays",
			detail: [
				...shortfalls.map(
					({ name, actual, expected: want }) =>
						`${name} waits ${formatDuration(actual)}, below the published ${formatDuration(want)}`,
				),
				...policy,
				...(uncompared.length > 0
					? [`no published value for ${uncompared.join(", ")}`]
					: []),
			].join("; "),
			remedy:
				"The published delays are a promise to tenants. Propose the delay back up (setFunctionDelay or updateDelay, through the timelock).",
		};
	if (!expected)
		return {
			id: "timelock-delays",
			level: "warn",
			label: "timelock delays not compared",
			detail: `no published delays to compare with; ${summary}`,
			remedy:
				"Give the deployment its profile's delays so a shortened delay is caught.",
		};
	if (uncompared.length > 0)
		return {
			id: "timelock-delays",
			level: "warn",
			label: "timelock delays not all compared",
			detail: `no published value for ${uncompared.join(", ")}; the others are at or above theirs`,
			remedy:
				"Give every delay the chain's profile publishes, so a shortened one is caught.",
		};
	return {
		id: "timelock-delays",
		level: "ok",
		label: "timelock delays at or above the published values",
		detail: summary,
	};
}

/**
 * One sentence per address rather than per role: a key that kept every role reads as that key and
 * its roles, not as four lines naming it four times.
 */
function describeRoleProblems(
	problems: readonly TimelockedRoleProblem[],
	timelock: Address,
): string {
	const byHolder = new Map<Address, string[]>();
	for (const { role, others } of problems)
		for (const holder of others)
			byHolder.set(holder, [...(byHolder.get(holder) ?? []), role]);
	const missing = problems
		.filter((problem) => problem.missing)
		.map((problem) => problem.role);
	return [
		...[...byHolder].map(
			([holder, roles]) => `${holder} also holds ${roles.join(", ")}`,
		),
		...(missing.length > 0
			? [`the timelock ${timelock} does not hold ${missing.join(", ")}`]
			: []),
	].join("; ");
}

/** The newest release this SDK's giano-contracts knows: a later one reads as no release here. */
const NEWEST_RELEASE =
	RELEASE_FINGERPRINTS.filter(
		(entry) => entry.contract === "GianoPaymaster",
	).at(-1)?.release ?? "none";

/** The implementation runs a contracts release (D13), whatever address it was deployed at. */
function implementationCheck({
	address,
	code,
}: NonNullable<HealthContext["implementation"]>): HealthCheck {
	const present = code !== undefined && code !== "0x";
	// Given the address, releaseOf also checks the code names itself in UUPS's `__self`.
	const release = present
		? releaseOf("GianoPaymaster", code, address)
		: undefined;
	return release
		? {
				id: "implementation",
				level: "ok",
				label: "implementation is a release",
				detail: `release ${release.release} at ${address}`,
			}
		: {
				id: "implementation",
				level: "fail",
				label: `implementation matches none of the releases this SDK knows (up to ${NEWEST_RELEASE})`,
				detail: present
					? `${address}, codehash ${keccak256(code)}`
					: address === zeroAddress
						? "no ERC-1967 implementation: the paymaster is not a UUPS proxy"
						: `no code at ${address}`,
				remedy: `If a release newer than ${NEWEST_RELEASE} has been cut, update the SDK (giano-contracts) and check again. Otherwise the paymaster runs code that is no release, so nobody reviewed it as one: find out who upgraded it, and upgrade to a release (UPGRADER_ROLE, through the timelock).`,
			};
}
