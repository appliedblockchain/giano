import type {
	PaymasterOverview,
	TimelockOperation,
} from "@appliedblockchain/giano-paymaster-sdk";
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

/** A tenant by the name an operator knows it by: its slug where the registry has one. */
const nameOf = (row: TenantRow) => row.registry?.slug ?? row.id;
const pathOf = (row: TenantRow) => tenantPath(row.registry?.slug ?? row.id);

/**
 * Everything on the Overview that needs an operator, most urgent first. Pure: the console reads
 * the chain, the registry and the timelock, and this decides what of it is a problem.
 *
 * `rows` is the registry joined to the roster; `ready` the timelock operations ready to execute;
 * `now` is unix seconds, for the stake's unlock time.
 */
export function attentionItems({
	overview,
	rows,
	ready,
	now,
	platformApi,
}: {
	overview: PaymasterOverview;
	rows: readonly TenantRow[];
	ready: readonly TimelockOperation[];
	now: number;
	platformApi: boolean;
}): AttentionItem[] {
	const items: AttentionItem[] = [];
	const { solvency, config, stake } = overview;

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

	if (!stake.staked || stake.withdrawTime > 0)
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

	for (const row of rows) {
		const status = row.registry?.status;
		if (status === "deleted" && !row.onChain) continue;
		const name = nameOf(row);

		if (row.onChain && row.onChain.deficit > 0n)
			items.push({
				key: `deficit:${row.id}`,
				kind: "deficit",
				subject: name,
				severity: "critical",
				title: `${name} is in deficit`,
				detail:
					"It cannot be sponsored until it is funded. Funding clears the deficit first, then credits the rest.",
				link: pathOf(row),
				linkLabel: "Fund",
			});
		else if (
			row.onChain &&
			row.onChain.balance === 0n &&
			row.onChain.enabled &&
			(status === undefined || status === "active")
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
			if (platformApi && row.state !== "unknown")
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

		if (status === "active" && row.state === "not-registered")
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
