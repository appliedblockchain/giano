import type { HealthCheck } from "@appliedblockchain/giano-paymaster-sdk";
import type { ChainStatus, ChainsStatus } from "./platform-api";
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
		id === "drift-enabled" ||
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
 * - Watcher lag: the watcher trails the head by its confirmations on purpose. Past 50 blocks
 *   wallet-api itself stops trusting the ledger (TENANT_DELETE_MAX_LEDGER_LAG_BLOCKS' default);
 *   past 1,000 the ledger is not following at all.
 */
export const CHAIN_THRESHOLDS = {
	headAgeWarnSeconds: 60,
	headAgeFailSeconds: 300,
	watcherLagWarnBlocks: 50,
	watcherLagFailBlocks: 1_000,
};

/**
 * The repository's local anvil devnets (`packages/contracts/chains.ts` names them). They mine only
 * when there is a transaction, so an idle one's head is hours old and says nothing about the node:
 * its age is shown, not judged.
 */
export const LOCAL_DEVNET_CHAIN_IDS: readonly number[] = [31337, 31338];

/** The checks for one chain wallet-api serves, worst first within each part. */
export function chainChecks(chain: ChainStatus): HealthCheck[] {
	const id = (part: string) => `chain-${chain.chainId}-${part}`;
	const checks: HealthCheck[] = [];
	const t = CHAIN_THRESHOLDS;

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
