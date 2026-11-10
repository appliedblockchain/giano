import type {
	HealthCheck,
	HealthReport,
} from "@appliedblockchain/giano-paymaster-sdk";
import type { ChainStatus, ChainsStatus } from "./platform-api";
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

/**
 * The thresholds that turn wallet-api's chain figures into a verdict (B3). They sit here, beside the
 * SDK's (giano-doctor's) deposit and stake thresholds, because wallet-api reports figures and leaves
 * the verdict to whoever reads them (specs/PLATFORM-ADMIN-SPECS.md §10.2).
 *
 * - Head age: every chain Giano serves makes a block within seconds; a minute without one is worth a
 *   look, five minutes is a node that has stopped following the chain.
 * - Watcher lag: the watcher trails the head by its confirmations on purpose. Past wallet-api's
 *   TENANT_DELETE_MAX_LEDGER_LAG_BLOCKS (the response's `maxLedgerLagBlocks`; 50 by default, and
 *   here when an older wallet-api does not say) it stops trusting the ledger; past 1,000 the ledger
 *   is not following at all.
 */
export const CHAIN_THRESHOLDS = {
	headAgeWarnSeconds: 60,
	headAgeFailSeconds: 300,
	watcherLagWarnBlocks: 50,
	watcherLagFailBlocks: 1_000,
};

export type ChainThresholds = typeof CHAIN_THRESHOLDS;

/** The thresholds for a chains response: the watcher's warning is wallet-api's own limit. */
export function chainThresholds(status?: ChainsStatus): ChainThresholds {
	const warn =
		status?.maxLedgerLagBlocks ?? CHAIN_THRESHOLDS.watcherLagWarnBlocks;
	return {
		...CHAIN_THRESHOLDS,
		watcherLagWarnBlocks: warn,
		watcherLagFailBlocks: Math.max(CHAIN_THRESHOLDS.watcherLagFailBlocks, warn),
	};
}

/**
 * The repository's local anvil devnets (`packages/contracts/chains.ts` names them). They mine only
 * when there is a transaction, so an idle one's head is hours old and says nothing about the node:
 * its age is shown, not judged.
 */
export const LOCAL_DEVNET_CHAIN_IDS: readonly number[] = [31337, 31338];

/** The checks for one chain wallet-api serves, worst first within each part. */
export function chainChecks(
	chain: ChainStatus,
	t: ChainThresholds = CHAIN_THRESHOLDS,
): HealthCheck[] {
	const id = (part: string) => `chain-${chain.chainId}-${part}`;
	const checks: HealthCheck[] = [];

	const probe = chain.lastProbe;
	checks.push(
		chain.registryStatus === "ready"
			? {
					id: id("status"),
					level: "ok",
					label: "served",
					detail: probe
						? `last probed ${new Date(probe.at).toLocaleTimeString()}`
						: "not probed since start-up",
				}
			: {
					id: id("status"),
					level: "fail",
					label: "not served",
					detail: `wallet-api marked this chain unavailable${probe?.detail ? `: ${probe.detail}` : ""}`,
					remedy:
						"Requests for this chain are refused until it is reachable and passes verification again; wallet-api retries every 15 seconds.",
				},
	);
	const failures = (chain.verification?.failures ?? []).filter(
		(failure) => failure.kind !== "unreachable",
	);
	if (failures.length > 0)
		checks.push({
			id: id("verification"),
			level: "fail",
			label: "verification failed",
			detail: failures.map((failure) => failure.kind).join(", "),
			remedy:
				"The endpoint, the EntryPoint or the factory is not what this chain is configured with. Check wallet-api's logs for the details.",
		});

	const { node } = chain;
	const onDemand = LOCAL_DEVNET_CHAIN_IDS.includes(chain.chainId);
	const age = onDemand ? 0 : (node.headAgeSeconds ?? 0);
	checks.push(
		!node.reachable
			? {
					id: id("node"),
					level: "fail",
					label: "node",
					detail: "did not answer within 3 seconds",
					remedy: "Check the chain's RPC endpoint and its provider.",
				}
			: {
					id: id("node"),
					level:
						age > t.headAgeFailSeconds
							? "fail"
							: age > t.headAgeWarnSeconds
								? "warn"
								: "ok",
					label: "node",
					detail: `head ${node.headBlock}, ${node.headAgeSeconds}s old${onDemand ? " (a local devnet mines on demand, so its age is not judged)" : ""}`,
					...(age > t.headAgeWarnSeconds
						? {
								remedy: `The newest block is older than ${t.headAgeWarnSeconds}s: the node may have stopped following the chain.`,
							}
						: {}),
				},
	);

	const { bundler } = chain;
	checks.push(
		!bundler.reachable
			? {
					id: id("bundler"),
					level: "fail",
					label: "bundler",
					detail: "did not answer within 3 seconds",
					remedy:
						"Operations for this chain cannot be submitted. Check the bundler service.",
				}
			: bundler.entryPointSupported === false
				? {
						id: id("bundler"),
						level: "fail",
						label: "bundler",
						detail: "does not list the configured EntryPoint",
						remedy:
							"The bundler serves a different EntryPoint than wallet-api submits to; every operation would be refused.",
					}
				: {
						id: id("bundler"),
						level: bundler.entryPointSupported === null ? "warn" : "ok",
						label: "bundler",
						detail:
							bundler.entryPointSupported === null
								? "answers, but would not say which EntryPoints it supports"
								: "answers, and lists the configured EntryPoint",
					},
	);

	const { paymaster } = chain;
	if (paymaster) {
		const lag = paymaster.watcherLagBlocks;
		checks.push(
			lag === null
				? {
						id: id("watcher"),
						level: "warn",
						label: "ledger watcher",
						detail: paymaster.lastSyncedBlock
							? "behind an unknown head"
							: "has never synced this chain",
						remedy:
							"wallet-api's ledger for this paymaster is not following the chain; check the watcher in its logs.",
					}
				: {
						id: id("watcher"),
						level:
							lag > t.watcherLagFailBlocks
								? "fail"
								: lag > t.watcherLagWarnBlocks
									? "warn"
									: "ok",
						label: "ledger watcher",
						detail: `${lag} block${lag === 1 ? "" : "s"} behind the head, at block ${paymaster.lastSyncedBlock}`,
						...(lag > t.watcherLagWarnBlocks
							? {
									remedy: `More than ${t.watcherLagWarnBlocks} blocks behind, wallet-api stops trusting the ledger for a tenant delete. Check the watcher in its logs.`,
								}
							: {}),
					},
		);
	}
	return checks;
}

/** The deployment-wide check: the one sponsorship signer every chain shares. */
export function signerCheck(
	signer: ChainsStatus["signer"],
): HealthCheck | undefined {
	if (signer === "disabled") return undefined;
	return signer === "ok"
		? {
				id: "signer",
				level: "ok",
				label: "sponsorship signer",
				detail: "answers, for every chain",
			}
		: {
				id: "signer",
				level: "fail",
				label: "sponsorship signer",
				detail: "unavailable",
				remedy:
					"No sponsorship can be authorised on any chain until it answers. Check the key service wallet-api signs with.",
			};
}
