import type {
	HealthCheck,
	HealthReport,
} from "@appliedblockchain/giano-paymaster-sdk";
import type {
	BundlerExecutor,
	ChainStatus,
	ChainsStatus,
} from "./platform-api";
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
	/**
	 * A bundler executor pays for every handleOps it sends; out of funds, submission through it stops
	 * (B7, D28). Judged by submissions left at the chain's gas price, not by an amount of ETH that
	 * means different things on different chains.
	 */
	executorWarnSubmissions: 100,
	executorFailSubmissions: 10,
	/** Gas one handleOps([op]) is taken to use: one operation with a paymaster stays well under it. */
	gasPerSubmission: 400_000n,
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

export type ExecutorStanding = {
	level: HealthCheck["level"];
	/** Submissions the balance pays for at the gas price; null when the gas price is unknown or 0. */
	submissions: number | null;
	/** Why the lane is stuck, if it is: held past the bundler's give-up time, or a transaction the bundler is not working on. */
	stuck: "held" | "mempool" | undefined;
	/** How long the lane has held its transaction, where wallet-api says. */
	heldSeconds: number | undefined;
};

/**
 * How an executor stands: empty or nearly so fails, low warns, a stuck lane warns. A lane is stuck
 * when it has held one transaction past what the bundler's replacements and cancellation can take
 * (`held`), or when the node holds a transaction from the executor that the bundler is not working
 * on (`mempool`: pending while the lane is idle, or more than one ahead, which only another process
 * sending from the same key can cause).
 */
export function executorStanding(
	executor: BundlerExecutor,
	gasPriceWei: string | null | undefined,
	lane: { stuckAfterSeconds?: number | null; now?: number } = {},
): ExecutorStanding {
	const t = CHAIN_THRESHOLDS;
	const balance = BigInt(executor.balanceWei);
	const perSubmission = gasPriceWei
		? BigInt(gasPriceWei) * t.gasPerSubmission
		: 0n;
	const submissions =
		perSubmission > 0n ? Number(balance / perSubmission) : null;
	const ahead = executor.pendingNonce - executor.latestNonce;
	const heldSeconds =
		executor.busy && executor.busySince
			? Math.max(
					0,
					Math.round(
						((lane.now ?? Date.now()) - Date.parse(executor.busySince)) / 1000,
					),
				)
			: undefined;
	const held =
		heldSeconds !== undefined &&
		lane.stuckAfterSeconds != null &&
		heldSeconds > lane.stuckAfterSeconds;
	const mempool = ahead > 1 || (ahead > 0 && !executor.busy);
	const stuck = held ? "held" : mempool ? "mempool" : undefined;
	const level =
		balance === 0n ||
		(submissions !== null && submissions < t.executorFailSubmissions)
			? "fail"
			: (submissions !== null && submissions < t.executorWarnSubmissions) ||
					stuck
				? "warn"
				: "ok";
	return { level, submissions, stuck, heldSeconds };
}

/** The bundler's executors on one chain, one check each; one warning where they are unknown. */
export function executorChecks(
	chain: ChainStatus,
	money: (wei: bigint) => string,
	now = Date.now(),
): HealthCheck[] {
	const { bundler } = chain;
	// Absent from a wallet-api older than B7: nothing to say, as for every phase 2 field (D11).
	if (!bundler.reachable || bundler.executors === undefined) return [];
	if (bundler.executors === null)
		return [
			bundler.executorsUnknown === "unavailable"
				? {
						id: `chain-${chain.chainId}-executors`,
						level: "warn",
						label: "bundler executors",
						detail:
							"the bundler did not report them in time, or its node failed, so they are not checked",
						remedy: `Check ${chain.name}'s node first, then the bundler's logs; they are read again on the next refresh.`,
					}
				: {
						id: `chain-${chain.chainId}-executors`,
						level: "warn",
						label: "bundler executors",
						detail: "the bundler does not report them, so they are not checked",
						remedy:
							"giano-bundler reports its executors; check this chain's bundler is giano-bundler and current.",
					},
		];
	const t = CHAIN_THRESHOLDS;
	return bundler.executors.map((executor, index) => {
		const { level, submissions, stuck, heldSeconds } = executorStanding(
			executor,
			bundler.gasPriceWei,
			{ stuckAfterSeconds: bundler.laneStuckAfterSeconds, now },
		);
		const balance = BigInt(executor.balanceWei);
		// Approximate: an operation's own gas limit and fee cap, and an L2's data fee, can need more.
		const covers =
			balance === 0n
				? ", nothing to pay gas with"
				: submissions === null
					? ""
					: `, about ${submissions.toLocaleString()} submission${submissions === 1 ? "" : "s"} at ${(Number(t.gasPerSubmission) / 1000).toLocaleString()}k gas and the current gas price (approximate)`;
		const lane = executor.busy
			? heldSeconds !== undefined
				? `submitting for ${formatHeld(heldSeconds)}`
				: "submitting"
			: "idle";
		const funds =
			balance === 0n ||
			(submissions !== null && submissions < t.executorWarnSubmissions);
		return {
			id: `chain-${chain.chainId}-executor-${executor.address.toLowerCase()}`,
			level,
			label: `bundler executor ${index + 1}`,
			detail: `${executor.address}: ${money(balance)}${covers}; ${lane}${stuck === "mempool" ? `, nonce ${executor.latestNonce} with ${executor.pendingNonce - executor.latestNonce} pending` : ""}`,
			...(level === "ok"
				? {}
				: {
						remedy: funds
							? `Fund this address on ${chain.name}: every operation it takes fails until it can pay for gas, and the bundler keeps giving it work.`
							: stuck === "held"
								? `This lane has held one transaction past the ${formatHeld(bundler.laneStuckAfterSeconds ?? 0)} the bundler's replacements and cancellation can take, and gets no new work until it is mined: check the bundler's logs and ${chain.name}'s node.`
								: "The node holds a transaction from this executor that the bundler is not working on (another process sending from the same key, or one the node kept after a restart): check the bundler's logs and the executor's pending transactions.",
					}),
		};
	});
}

/** 90 → "2 min", 4000 → "1 h 7 min". */
function formatHeld(seconds: number): string {
	const minutes = Math.round(seconds / 60);
	if (minutes < 1) return `${seconds} s`;
	if (minutes < 60) return `${minutes} min`;
	return `${Math.floor(minutes / 60)} h ${minutes % 60} min`;
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
	money: (wei: bigint) => string = (wei) => `${wei} wei`,
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
	checks.push(...executorChecks(chain, money));
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
