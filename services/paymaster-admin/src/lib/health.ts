import type { HealthCheck } from "@appliedblockchain/giano-paymaster-sdk";
import { TAB_PATHS } from "./router";

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
