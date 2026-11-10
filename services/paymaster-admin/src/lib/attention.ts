import type {
	HealthCheck,
	PaymasterOverview,
	TimelockOperation,
} from "@appliedblockchain/giano-paymaster-sdk";
import { executorStanding } from "./health";
import type { ChainStatus } from "./platform-api";
import { TAB_PATHS, tenantPath } from "./router";
import type { TenantRow } from "./tenants";

export type AttentionSeverity = "critical" | "warning" | "timelock";

/** One condition that needs an operator, and where it is fixed (openspec N10). */
export type AttentionItem = {
	key: string;
	/** What kind of condition, for grouping many of one kind into a line. */
	kind: string;
	/** The tenant it is about, by the name an operator knows it by; absent for the paymaster's own. */
	subject?: string;
	/** On a grouped line: the first few it is about, each linking to its own page, and how many more. */
	members?: { name: string; link: string }[];
	more?: number;
	severity: AttentionSeverity;
	title: string;
	detail: string;
	/** Where the fix is: a tenant page, a tab, or an operation in the Timelock tab. */
	link: string;
	linkLabel: string;
};

const ORDER: Record<AttentionSeverity, number> = {
	critical: 0,
	warning: 1,
	timelock: 2,
};

/**
 * What the Overview has read, so "nothing found" is never said of what was not read (openspec N10).
 * `registry` is absent without the platform API, and `timelock` without a timelock.
 */
export type AttentionSources = {
	registry?: {
		/** The first registry read has succeeded: whether a tenant has a registry row is known. */
		known: boolean;
		/** The last read failed. What an earlier one found stays, and this is shown. */
		error?: string;
		/** Only the deleted tenants could not be read: a tenant missing from the registry may be one. */
		deletedError?: string;
	};
	timelock?: {
		/** A read has finished, either way. */
		settled: boolean;
		/** A read has succeeded. */
		read: boolean;
		error?: string;
	};
	/**
	 * False on a paymaster that predates the on-chain roster: the roster comes from one window of
	 * logs, so a tenant registered before it reads as not registered.
	 */
	rosterOnChain: boolean;
	/**
	 * wallet-api's chain status (B3, B7), where it serves it: the bundler's executors come from it.
	 * Absent without the platform API, or from a wallet-api that does not serve it.
	 */
	chains?: {
		/** No answer yet, and no failure either. */
		pending: boolean;
		/** The last read failed. What an earlier one found stays, and this is shown. */
		error?: string;
		/** A read has succeeded. */
		read: boolean;
	};
	/** Health's checks: any that fails and is not already an item here becomes one. */
	health?: readonly HealthCheck[];
	/** Health checks still waiting for a read (useHealth's `pending`), by name. */
	healthPending?: readonly string[];
};

/** Health checks the Overview already states in its own words. */
const COVERED_BY_OVERVIEW = new Set([
	"solvency",
	"paused",
	"stake-unlocking",
	"tenant-deficits",
	"tenants-funded",
]);

/** The sources not read yet, by name: until they are, the Overview cannot say all is well. */
export function unreadSources(sources: AttentionSources): string[] {
	const unread: string[] = [];
	if (sources.registry && !sources.registry.known && !sources.registry.error)
		unread.push("the tenant registry");
	if (sources.timelock && !sources.timelock.settled)
		unread.push("the timelock");
	if (sources.chains?.pending) unread.push("the chains");
	for (const label of sources.healthPending ?? [])
		if (!unread.includes(label)) unread.push(label);
	return unread;
}

/** A tenant by the name an operator knows it by: its slug where the registry has one. */
const nameOf = (row: TenantRow) => row.registry?.slug ?? row.id;
const pathOf = (row: TenantRow) => tenantPath(row.registry?.slug ?? row.id);

/**
 * Everything on the Overview that needs an operator, most urgent first. Pure: the console reads
 * the chain, the registry and the timelock, and this decides what of it is a problem.
 *
 * `rows` is the registry joined to the roster; `ready` the timelock operations ready to execute;
 * `now` is unix seconds, for the stake's unlock time. `chain` is wallet-api's status of the selected
 * chain, where it serves one, for the bundler's executors (B7).
 */
export function attentionItems({
	overview,
	rows,
	ready,
	now,
	sources,
	chain,
}: {
	overview: PaymasterOverview;
	rows: readonly TenantRow[];
	ready: readonly TimelockOperation[];
	now: number;
	sources: AttentionSources;
	chain?: ChainStatus;
}): AttentionItem[] {
	const items: AttentionItem[] = [];

	// An executor out of funds fails every operation the bundler hands it on this chain.
	for (const executor of chain?.bundler.executors ?? []) {
		const { level, submissions } = executorStanding(
			executor,
			chain?.bundler.gasPriceWei,
		);
		if (level !== "fail") continue;
		const short = `${executor.address.slice(0, 6)}…${executor.address.slice(-4)}`;
		const empty = BigInt(executor.balanceWei) === 0n;
		items.push({
			key: `executor:${executor.address.toLowerCase()}`,
			kind: "executor",
			severity: "critical",
			title: `Bundler executor ${short} ${empty ? "is empty" : "is nearly empty"}`,
			detail: `It signs and pays for the transactions that submit user operations, and every one it takes fails until it can pay for gas.${empty || submissions === null ? "" : ` About ${submissions} submission${submissions === 1 ? "" : "s"} left at the current gas price.`} Fund ${executor.address}.`,
			link: TAB_PATHS.health,
			linkLabel: "Health",
		});
	}
	const { solvency, config, stake } = overview;
	const { registry, timelock } = sources;
	// The registry rules wait for its first successful read: before it, every row lacks a registry
	// row, which says nothing. "No registry row" also waits for the deleted tenants.
	const registryKnown = registry === undefined || registry.known;
	const rowlessKnown =
		registry !== undefined && registry.known && !registry.deletedError;

	if (registry?.error)
		items.push({
			key: "unread:registry",
			kind: "unread",
			severity: "warning",
			title: "Could not read the tenant registry",
			detail: `${registry.error}. ${registry.known ? "What it last returned is shown." : "The checks that need it are skipped until it is read."}`,
			link: TAB_PATHS.tenants,
			linkLabel: "Tenants",
		});
	else if (registry?.deletedError)
		items.push({
			key: "unread:deleted",
			kind: "unread",
			severity: "warning",
			title: "Could not read the deleted tenants",
			detail: `${registry.deletedError}. An on-chain tenant missing from the registry may be a deleted one, so it is not listed as having no registry row.`,
			link: TAB_PATHS.tenants,
			linkLabel: "Tenants",
		});
	if (timelock?.error)
		items.push({
			key: "unread:timelock",
			kind: "unread",
			severity: "warning",
			title: "Could not read the timelock",
			detail: `${timelock.error}. ${timelock.read ? "What it last returned is shown." : "Operations waiting or ready are not known until it is read."}`,
			link: TAB_PATHS.timelock,
			linkLabel: "Timelock",
		});

	if (sources.chains?.error)
		items.push({
			key: "unread:chains",
			kind: "unread",
			severity: "warning",
			title: "Could not read the chains' status",
			detail: `${sources.chains.error}. ${sources.chains.read ? "What it last returned is shown." : "The bundler's executors are not checked until it is read."}`,
			link: TAB_PATHS.health,
			linkLabel: "Health",
		});

	if (!solvency.holds)
		items.push({
			key: "insolvent",
			kind: "insolvent",
			severity: "critical",
			title: "The accounting invariant is breached",
			detail:
				"What the paymaster owes tenants and the treasury exceeds its deposit. Stop issuing sponsorships and investigate before anything else.",
			link: TAB_PATHS.health,
			linkLabel: "Health",
		});

	if (config.paused)
		items.push({
			key: "paused",
			kind: "paused",
			severity: "critical",
			title: "The paymaster is paused",
			detail:
				"No new sponsorship is accepted for any tenant. Withdrawals still work.",
			link: TAB_PATHS.paymaster,
			linkLabel: "Unpause",
		});

	const stakeItem = !stake.staked || stake.withdrawTime > 0;
	if (stakeItem)
		items.push({
			key: "stake",
			kind: "stake",
			severity: "critical",
			title:
				stake.withdrawTime > 0
					? stake.withdrawTime <= now
						? "The stake is unlocked"
						: "The stake is unlocking"
					: "The paymaster is not staked",
			detail:
				"Bundlers refuse operations from an unstaked paymaster, so nothing is sponsored.",
			link: TAB_PATHS.paymaster,
			linkLabel: "Stake",
		});

	// Whatever Health fails that the Overview does not already say: no signing key, a deposit or a
	// stake below the minimum, and the checks later layers add. The stake check is said above when
	// the stake is missing or unlocking.
	for (const check of sources.health ?? [])
		if (
			check.level === "fail" &&
			!COVERED_BY_OVERVIEW.has(check.id) &&
			!(check.id === "stake" && stakeItem)
		)
			items.push({
				key: `health:${check.id}`,
				kind: `health:${check.id}`,
				severity: "critical",
				title: check.label.charAt(0).toUpperCase() + check.label.slice(1),
				detail: check.remedy ? `${check.detail} ${check.remedy}` : check.detail,
				link: TAB_PATHS.health,
				linkLabel: "Health",
			});

	for (const row of rows) {
		const status = row.registry?.status;
		if (status === "deleted" && !row.onChain) continue;
		const name = nameOf(row);
		// A tenant being wound down is not asked to be funded, as nextStep does not.
		const woundDown = status === "suspended" || status === "deleted";

		if (row.onChain && row.onChain.deficit > 0n)
			items.push({
				key: `deficit:${row.id}`,
				kind: "deficit",
				subject: name,
				severity: woundDown ? "warning" : "critical",
				title: woundDown
					? `${name} is ${status} and in deficit`
					: `${name} is in deficit`,
				detail: woundDown
					? "It is being wound down, so it is not asked to be funded; the deficit stays on the paymaster's books until it is."
					: "It cannot be sponsored until it is funded. Funding clears the deficit first, then credits the rest.",
				link: pathOf(row),
				linkLabel: woundDown ? "Open" : "Fund",
			});
		else if (
			row.onChain &&
			row.onChain.balance === 0n &&
			row.onChain.enabled &&
			// Only a tenant wallet-api knows to be active, or any without the platform API: funding
			// one wallet-api does not know, or before the registry is read, is not the ask.
			(registry === undefined ? true : row.registry?.status === "active")
		)
			items.push({
				key: `unfunded:${row.id}`,
				kind: "unfunded",
				subject: name,
				severity: "warning",
				title: `${name} has no balance`,
				detail:
					"It is registered and enabled, but nothing it does can be sponsored until it is funded.",
				link: pathOf(row),
				linkLabel: "Fund",
			});

		if (!row.registry) {
			if (rowlessKnown && row.state !== "unknown")
				items.push({
					key: `unregistry:${row.id}`,
					kind: "unregistry",
					subject: name,
					severity: "warning",
					title: `${name} is on chain with no registry row`,
					detail:
						"The paymaster has a tenant wallet-api does not know: another deployment's tenant on a shared paymaster, or a registration whose tenant was never created.",
					link: pathOf(row),
					linkLabel: "Open",
				});
			continue;
		}

		if (!registryKnown) continue;
		if (
			status === "active" &&
			row.state === "not-registered" &&
			// Without an on-chain roster, one read from a window of logs: a tenant registered before
			// it reads as not registered. The Tenants tab says so; here it is not claimed.
			sources.rosterOnChain
		)
			items.push({
				key: `unregistered:${row.id}`,
				kind: "unregistered",
				subject: name,
				severity: "warning",
				title: `${name} is not registered on this chain`,
				detail:
					"It exists in wallet-api, but this paymaster cannot fund or sponsor it until it is registered.",
				link: pathOf(row),
				linkLabel: "Register",
			});
		else if (status === "active" && row.state === "disabled")
			items.push({
				key: `disabled:${row.id}`,
				kind: "disabled",
				subject: name,
				severity: "warning",
				title: `${name} is active but disabled on chain`,
				detail:
					"wallet-api serves it, and the paymaster refuses to sponsor it.",
				link: pathOf(row),
				linkLabel: "Enable",
			});
		else if (
			(status === "suspended" || status === "deleted") &&
			row.state === "enabled"
		)
			items.push({
				key: `enabled:${row.id}`,
				kind: "enabled",
				subject: name,
				severity: "critical",
				title: `${name} is ${status} but still enabled on chain`,
				detail:
					"An authorisation signed before it was suspended stays valid until it expires. Disabling it on the paymaster closes that window.",
				link: pathOf(row),
				linkLabel: "Disable",
			});
	}

	for (const operation of ready)
		items.push({
			key: `ready:${operation.id}`,
			kind: "ready",
			severity: "timelock",
			title: "A timelock operation is ready to execute",
			detail: operation.calls
				.map((call) => call.decoded?.summary ?? `a call to ${call.target}`)
				.join("; "),
			link: `${TAB_PATHS.timelock}#${operation.id}`,
			linkLabel: "Execute",
		});

	return items.sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);
}

const GROUP_TITLES: Record<string, (count: number) => string> = {
	deficit: (count) => `${count} tenants are in deficit`,
	unfunded: (count) => `${count} tenants have no balance`,
	unregistry: (count) => `${count} tenants are on chain with no registry row`,
	unregistered: (count) => `${count} tenants are not registered on this chain`,
	disabled: (count) => `${count} tenants are active but disabled on chain`,
	enabled: (count) =>
		`${count} tenants are suspended or deleted but still enabled on chain`,
	unread: (count) => `${count} sources could not be read`,
	ready: (count) => `${count} timelock operations are ready to execute`,
};

/** What a grouped line says, in the plural: the single item's sentence is about one tenant. */
const GROUP_DETAILS: Record<string, string> = {
	deficit:
		"None of them can be sponsored until funded. Funding clears a deficit first, then credits the rest.",
	unfunded:
		"They are registered and enabled, but nothing they do can be sponsored until they are funded.",
	unregistry:
		"The paymaster has tenants wallet-api does not know: another deployment's on a shared paymaster, or registrations whose tenants were never created.",
	unregistered:
		"They exist in wallet-api, but this paymaster cannot fund or sponsor them until they are registered.",
	disabled:
		"wallet-api serves them, and the paymaster refuses to sponsor them.",
	enabled:
		"Authorisations signed before they were suspended stay valid until they expire. Disabling them on the paymaster closes that window.",
	ready: "Each can be executed from the Timelock tab.",
};

/**
 * More than `limit` of one kind become one line, naming the first few: twenty tenants with no
 * balance are one thing to look at, and listed one by one they push everything else off the page.
 * The line keeps the place and severity of the first of its kind, and links to where they are listed.
 */
export function groupAttention(
	items: readonly AttentionItem[],
	limit = 3,
): AttentionItem[] {
	const byKind = new Map<string, AttentionItem[]>();
	for (const item of items)
		byKind.set(item.kind, [...(byKind.get(item.kind) ?? []), item]);
	const grouped: AttentionItem[] = [];
	const done = new Set<string>();
	for (const item of items) {
		const same = byKind.get(item.kind) ?? [];
		if (same.length <= limit || !GROUP_TITLES[item.kind]) {
			grouped.push(item);
			continue;
		}
		if (done.has(item.kind)) continue;
		done.add(item.kind);
		const named = same.filter((entry) => entry.subject !== undefined);
		grouped.push({
			...item,
			key: `group:${item.kind}`,
			subject: undefined,
			title: GROUP_TITLES[item.kind](same.length),
			detail: GROUP_DETAILS[item.kind] ?? item.detail,
			members: named
				.slice(0, limit)
				.map((entry) => ({ name: entry.subject as string, link: entry.link })),
			more: Math.max(named.length - limit, 0),
			link: item.kind === "ready" ? TAB_PATHS.timelock : TAB_PATHS.tenants,
			linkLabel: item.kind === "ready" ? "Timelock" : "Tenants",
		});
	}
	return grouped;
}
