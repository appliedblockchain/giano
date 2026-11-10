import type {
	HealthCheck,
	HealthReport,
} from "@appliedblockchain/giano-paymaster-sdk";
import { TAB_PATHS } from "./router";

/** A check the console has not been able to make yet: shown as being read, never as a pass. */
export type PendingCheck = { id: string; label: string };

/**
 * The report, and the checks still waiting for a read. Until `pending` is empty, `level` "ok" says
 * only that every check made so far passes.
 */
export type ConsoleHealth = HealthReport & { pending: PendingCheck[] };

/** "the implementation and the timelock": what Health is still reading, for a summary line. */
export function pendingText(pending: readonly { label: string }[]): string {
	const labels = pending.map((entry) => entry.label);
	return labels.length <= 1
		? (labels[0] ?? "")
		: `${labels.slice(0, -1).join(", ")} and ${labels[labels.length - 1]}`;
}

/** What the console has read of the inputs `assessHealth` takes beyond the overview. */
export type HealthReads = {
	implementationRead: boolean;
	implementationError: string | undefined;
	timelockConfigured: boolean;
	timelockRead: boolean;
	timelockError: string | undefined;
};

/**
 * The report as the console shows it: a check whose input has not been read is `pending`, and one
 * whose read failed is a warning. Never left out, so Health cannot say "every check passes" about
 * something it did not check (B2).
 */
export function withReads(
	report: HealthReport,
	reads: HealthReads,
): ConsoleHealth {
	const pending: PendingCheck[] = [];
	let checks: HealthCheck[] = [...report.checks];

	if (reads.implementationError)
		checks = [
			...checks.filter((check) => check.id !== "implementation"),
			{
				id: "implementation",
				level: "warn",
				label: "could not read the implementation",
				detail: reads.implementationError,
				remedy:
					"Whether the paymaster runs a release is not checked until it is read. Refresh, and check the RPC endpoint if it keeps failing.",
			},
		];
	else if (!reads.implementationRead)
		pending.push({ id: "implementation", label: "the implementation" });

	// A configured timelock not read yet is not "no timelock": until it is, there is no verdict,
	// neither the no-timelock warning nor its "exactly one holder" role checks.
	if (reads.timelockConfigured && !reads.timelockRead) {
		checks = checks.filter(
			(check) => check.id !== "timelock" && !check.id.startsWith("role-"),
		);
		if (reads.timelockError)
			checks.push({
				id: "timelock-read",
				level: "warn",
				label: "could not read the timelock",
				detail: reads.timelockError,
				remedy:
					"The timelocked roles and delays are not checked until it is read. Reload it on the Timelock tab.",
			});
		else pending.push({ id: "timelock", label: "the timelock" });
	}

	const level = checks.some((check) => check.level === "fail")
		? "fail"
		: checks.some((check) => check.level === "warn")
			? "warn"
			: "ok";
	return { level, checks, pending };
}

export type HealthGroup = "funds" | "keys" | "registry";

export const HEALTH_GROUPS: {
	group: HealthGroup;
	title: string;
	subtitle: string;
}[] = [
	{
		group: "funds",
		title: "Funds",
		subtitle:
			"The deposit, what it owes, the stake bundlers require, and every tenant's balance.",
	},
	{
		group: "keys",
		title: "Keys and roles",
		subtitle:
			"Who can authorise a sponsorship, and who holds each power over the paymaster.",
	},
	{
		group: "registry",
		title: "Registry and chain",
		subtitle:
			"Whether the paymaster is accepting work, and whether wallet-api and the chain agree.",
	},
];

const FUNDS = new Set([
	"solvency",
	"deposit",
	"stake",
	"stake-unlocking",
	"tenant-deficits",
	"tenants-funded",
]);
const KEYS = new Set([
	"signers",
	"no-superuser",
	"timelock",
	"timelock-read",
	"timelocked-roles",
	"timelock-delays",
	"implementation",
]);

/** The group an SDK check belongs in. A check the console does not know goes with the chain. */
export function checkGroup(id: string): HealthGroup {
	if (FUNDS.has(id)) return "funds";
	if (KEYS.has(id) || id.startsWith("role-")) return "keys";
	return "registry";
}

/** Where a check's remedy is carried out, and what to call the link. */
export function checkLink(id: string): { to: string; label: string } {
	if (
		id === "tenant-deficits" ||
		id === "tenants-funded" ||
		id === "registry-rows" ||
		id === "ledger"
	)
		return { to: TAB_PATHS.tenants, label: "Tenants" };
	if (
		id === "no-superuser" ||
		id === "timelock" ||
		id === "timelocked-roles" ||
		id.startsWith("role-")
	)
		return { to: TAB_PATHS.roles, label: "Roles" };
	if (id === "timelock-delays" || id === "timelock-read")
		return { to: TAB_PATHS.timelock, label: "Timelock" };
	if (id === "solvency") return { to: TAB_PATHS.overview, label: "Overview" };
	return { to: TAB_PATHS.paymaster, label: "Paymaster" };
}

export function groupChecks(
	checks: readonly HealthCheck[],
): Record<HealthGroup, HealthCheck[]> {
	const groups: Record<HealthGroup, HealthCheck[]> = {
		funds: [],
		keys: [],
		registry: [],
	};
	for (const check of checks) groups[checkGroup(check.id)].push(check);
	return groups;
}
