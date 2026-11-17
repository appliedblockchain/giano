/**
 * The argument rules of `provision:paymaster` (scripts/provision-paymaster.ts), kept here so they can
 * be tested without a chain. They run before the first transaction. The operator wrapper
 * (deploy/contracts/provision-paymaster.sh) checks the same mainnet rules earlier, but running the
 * script directly (deploy/contracts/README.md, the low-level path) must not skip them (#298 review).
 */
import { getAddress } from "viem";
import { parseDuration } from "../timelock";

/** The immediate roles, sent directly rather than through the timelock: one holder each on a mainnet. */
export const IMMEDIATE_ROLES = [
	"signer-admin",
	"param-admin",
	"pauser",
	"stake-admin",
	"tenant-admin",
	"fee-collector",
] as const;

/**
 * What is wrong with the role topology for a mainnet: every role on one address, an immediate role
 * with no holder, one address holding several, or a holder that is the operator key itself (which
 * holds ROLE_ADMIN until the hand-off, so an immediate role would sit beside it). Empty when fine,
 * and always empty off a mainnet.
 */
export function mainnetRoleProblems(options: {
	mainnet: boolean;
	grantAllTo?: string;
	/** `--role-holder-<role>` values by role flag, already checked to be addresses. */
	holders: Record<string, string | undefined>;
	operator: string;
}): string[] {
	if (!options.mainnet) return [];
	if (options.grantAllTo)
		return [
			"--grant-all-to puts every role on one address; a mainnet refuses it. Name a --role-holder-* per immediate role",
		];
	const problems: string[] = [];
	const missing = IMMEDIATE_ROLES.filter((role) => !options.holders[role]);
	if (missing.length)
		problems.push(
			`a mainnet names a holder for every immediate role; missing: ${missing.map((r) => `--role-holder-${r}`).join(", ")}`,
		);
	const operator = getAddress(options.operator);
	const byHolder = new Map<string, string[]>();
	for (const role of IMMEDIATE_ROLES) {
		const holder = options.holders[role];
		if (!holder) continue;
		const address = getAddress(holder);
		byHolder.set(address, [...(byHolder.get(address) ?? []), role]);
	}
	for (const [address, roles] of byHolder) {
		if (address === operator)
			problems.push(
				`${address} is the operator key, which holds ROLE_ADMIN until the hand-off; a mainnet gives ${roles.join(", ")} to another holder`,
			);
		else if (roles.length > 1)
			problems.push(
				`a mainnet gives each immediate role its own holder; ${address} is named for ${roles.join(", ")}`,
			);
	}
	return problems;
}

/**
 * ERC-7562 bundlers treat a paymaster as staked only with an unstake delay of at least a day, so a
 * mainnet needs that much (#298 review).
 */
export const MIN_MAINNET_UNSTAKE_DELAY = 86_400;

/**
 * `value` as an EntryPoint unstake delay in seconds: `90`, `6h`, `1d` as for the timelock delays,
 * above zero and within uint32 (`addStake`'s type), and at least a day on a mainnet. Checked with the
 * other arguments, so a typo stops the run before the signer or anything else has gone out (G42 R6).
 */
export function unstakeDelaySeconds(
	value: string,
	options: { mainnet: boolean },
): number {
	let seconds: number;
	try {
		seconds = parseDuration(value);
	} catch {
		throw new Error(
			`--unstake-delay is not a duration (seconds, or a number with s, m, h, d or w): ${value}`,
		);
	}
	if (!Number.isSafeInteger(seconds) || seconds <= 0 || seconds > 0xffffffff)
		throw new Error(
			`--unstake-delay must be between 1 second and ${0xffffffff} seconds, got: ${value}`,
		);
	if (options.mainnet && seconds < MIN_MAINNET_UNSTAKE_DELAY)
		throw new Error(
			`--unstake-delay on a mainnet is at least ${MIN_MAINNET_UNSTAKE_DELAY} seconds (1d): bundlers treat a shorter delay as unstaked (ERC-7562), got: ${value}`,
		);
	return seconds;
}
