import type { TenantView } from "@appliedblockchain/giano-paymaster-sdk";
import type { TenantStatus, TenantSummary } from "./platform-api";

/** Where a tenant stands on one chain's paymaster, matched on tenant id. */
export type OnChainState =
	| "enabled"
	| "disabled"
	| "not-registered"
	| "unknown";

/**
 * One tenant as the Tenants tab lists it (openspec platform-console-tenants): its registry row, its
 * entry on the selected chain's roster, or both — joined on the id the two share.
 */
export type TenantRow = {
	/** The UUID, lowercase. */
	id: string;
	registry: TenantSummary | undefined;
	onChain: TenantView | undefined;
	state: OnChainState;
};

export type NextStep = "register" | "fund";

/**
 * Registry rows newest first, then roster entries no registry row accounts for. `roster` undefined
 * means the paymaster has not been read, which is not the same as "registered nowhere".
 */
export function joinTenants(
	registry: readonly TenantSummary[] | undefined,
	roster: readonly TenantView[] | undefined,
): TenantRow[] {
	const byId = new Map(
		(roster ?? []).map((tenant) => [tenant.uuid.toLowerCase(), tenant]),
	);
	const rows: TenantRow[] = [...(registry ?? [])]
		.sort((a, b) => b.createdAt.localeCompare(a.createdAt))
		.map((tenant) => {
			const onChain = byId.get(tenant.id.toLowerCase());
			return {
				id: tenant.id.toLowerCase(),
				registry: tenant,
				onChain,
				state: stateOf(roster, onChain),
			};
		});
	const known = new Set(rows.map((row) => row.id));
	for (const [id, onChain] of byId)
		if (!known.has(id))
			rows.push({
				id,
				registry: undefined,
				onChain,
				state: stateOf(roster, onChain),
			});
	return rows;
}

function stateOf(
	roster: readonly TenantView[] | undefined,
	onChain: TenantView | undefined,
): OnChainState {
	if (!roster) return "unknown";
	if (!onChain) return "not-registered";
	return onChain.enabled ? "enabled" : "disabled";
}

/** The on-chain step a tenant is waiting for, if any. Nothing is suggested for a tenant being wound down. */
export function nextStep(row: TenantRow): NextStep | undefined {
	if (row.registry && row.registry.status !== "active") return undefined;
	if (row.registry && row.state === "not-registered") return "register";
	if (row.onChain && row.onChain.deficit > 0n) return "fund";
	return undefined;
}

/**
 * The on-chain writes the registry status rules out, each with the reason shown beside it. A deleted
 * tenant is offered none of Register (permanent: the roster only grows), Fund or Enable; a suspended
 * one may not be enabled, which would undo the suspension on this chain. Disable is never ruled
 * out: it is how a tenant is wound down.
 *
 * `status` is undefined for a tenant the registry does not have (or with no registry at all), and
 * `"unknown"` while the registry could not say: before its first read, or when the deleted tenants
 * could not be read. Then the tenant may be deleted, so the same three wait.
 */
export function onChainBlocks(status: TenantStatus | "unknown" | undefined): {
	register?: string;
	fund?: string;
	enable?: string;
} {
	if (status === "deleted") {
		const reason = "The tenant is deleted in the registry.";
		return { register: reason, fund: reason, enable: reason };
	}
	if (status === "unknown") {
		const reason =
			"The registry has not been read in full, so the tenant may be deleted. It is read again with the next refresh.";
		return { register: reason, fund: reason, enable: reason };
	}
	if (status === "suspended")
		return {
			enable: "The tenant is suspended in the registry: resume it first.",
		};
	return {};
}

/**
 * Something an operator should look at: a deficit, an active tenant registered and enabled with no
 * balance, a registry and a paymaster that disagree about whether the tenant may be sponsored, an
 * active tenant not yet registered, or an on-chain tenant with no registry row. The same conditions
 * the Overview lists, so the Tenants tab's filter and the Overview agree.
 *
 * `registryKnown` is whether there is a registry and it has been read. Without one, every row lacks
 * a registry row, which says nothing about the tenant, so that rule does not apply.
 */
export function needsAttention(
	row: TenantRow,
	registryKnown: boolean,
): boolean {
	if (row.onChain && row.onChain.deficit > 0n) return true;
	// Registered, enabled and empty, as the Overview lists it: nothing it does can be sponsored.
	if (
		row.onChain?.enabled &&
		row.onChain.balance === 0n &&
		(row.registry ? row.registry.status === "active" : !registryKnown)
	)
		return true;
	if (!row.registry) return registryKnown && row.state !== "unknown";
	const status = row.registry.status;
	if (status === "active")
		return row.state === "disabled" || row.state === "not-registered";
	return row.state === "enabled";
}

export type TenantFilter = "all" | "active" | "suspended" | "attention";

export function filterTenants(
	rows: readonly TenantRow[],
	{
		query,
		filter,
		includeDeleted,
		registryKnown,
	}: {
		query: string;
		filter: TenantFilter;
		includeDeleted: boolean;
		/** As for {@link needsAttention}. */
		registryKnown: boolean;
	},
): TenantRow[] {
	const needle = query.trim().toLowerCase();
	return rows.filter((row) => {
		const status: TenantStatus | undefined = row.registry?.status;
		if (status === "deleted" && !includeDeleted) return false;
		if (filter === "active" && status !== "active") return false;
		if (filter === "suspended" && status !== "suspended") return false;
		if (filter === "attention" && !needsAttention(row, registryKnown))
			return false;
		if (!needle) return true;
		return [
			row.id,
			row.registry?.slug,
			row.registry?.rpName,
			row.registry?.walletOrigin,
		]
			.filter((value): value is string => value !== undefined)
			.some((value) => value.toLowerCase().includes(needle));
	});
}

export type TenantTotals = {
	/** Sum of on-chain balances. */
	held: bigint;
	/** Tenants registered on the selected chain. */
	onChain: number;
	deficit: bigint;
	/** On-chain tenants with no registry row. */
	unregistered: number;
};

/** Totals for the whole roster on the selected chain, whatever the list is filtered to. */
export function tenantTotals(rows: readonly TenantRow[]): TenantTotals {
	const totals: TenantTotals = {
		held: 0n,
		onChain: 0,
		deficit: 0n,
		unregistered: 0,
	};
	for (const row of rows) {
		if (!row.onChain) continue;
		totals.held += row.onChain.balance;
		totals.deficit += row.onChain.deficit;
		totals.onChain += 1;
		if (!row.registry) totals.unregistered += 1;
	}
	return totals;
}

/**
 * A poll's first page of a tenant's history, folded into what the operator has loaded. When the
 * page overlaps the loaded entries, its new entries go on top and everything older stays, with the
 * cursor that loads past them (`keepCursor`). When it does not (more changed since than one page
 * holds), there is a gap the loaded entries cannot bridge, so the page replaces them and its own
 * cursor applies.
 */
export function mergeFirstPage<T extends { id: string }>(
	loaded: readonly T[],
	page: readonly T[],
): { entries: T[]; keepCursor: boolean } {
	if (loaded.length === 0) return { entries: [...page], keepCursor: false };
	if (page.length === 0) return { entries: [...loaded], keepCursor: true };
	const known = new Set(loaded.map((entry) => entry.id));
	if (!page.some((entry) => known.has(entry.id)))
		return { entries: [...page], keepCursor: false };
	const fresh = page.filter((entry) => !known.has(entry.id));
	return { entries: [...fresh, ...loaded], keepCursor: true };
}

/** Fields of a tenant snapshot that change on every write and say nothing about what changed. */
const BOOKKEEPING = new Set(["version", "updatedAt", "statusChangedAt"]);

export type FieldChange = { field: string; before: unknown; after: unknown };

/**
 * What a history entry changed (openspec K10): the fields whose value differs between its before
 * and after snapshots. A create has no before and a delete no after; each lists every field.
 */
export function historyChanges(
	before: Record<string, unknown> | null,
	after: Record<string, unknown> | null,
): FieldChange[] {
	const fields = new Set([
		...Object.keys(before ?? {}),
		...Object.keys(after ?? {}),
	]);
	const changes: FieldChange[] = [];
	for (const field of fields) {
		if (BOOKKEEPING.has(field)) continue;
		const was = before?.[field];
		const now = after?.[field];
		if (JSON.stringify(was) !== JSON.stringify(now))
			changes.push({ field, before: was, after: now });
	}
	return changes;
}

export type LedgerRow = {
	chainId: number;
	balanceWei: string;
	deficitWei: string;
	lastSyncedBlock: string | null;
};

export type LedgerComparison =
	| { kind: "agrees" }
	| { kind: "no-ledger" }
	| {
			kind: "differs";
			ledgerBalance: bigint;
			ledgerDeficit: bigint;
			/**
			 * Blocks the ledger is behind the block the chain was read at; undefined if it never synced.
			 * Negative when the ledger has synced past that block: then the console's read is the older side.
			 */
			lag: bigint | undefined;
	  };

/**
 * wallet-api's ledger against the paymaster, as read by the console (openspec D10). Approximate: the
 * console compares at the block it read, and only the ledger's `lastSyncedBlock` says how far behind
 * that the ledger is.
 */
export function compareLedger(
	ledger: LedgerRow | undefined,
	onChain: Pick<TenantView, "balance" | "deficit"> | undefined,
	readAt: bigint | undefined,
): LedgerComparison {
	if (!ledger) return onChain ? { kind: "no-ledger" } : { kind: "agrees" };
	const ledgerBalance = BigInt(ledger.balanceWei);
	const ledgerDeficit = BigInt(ledger.deficitWei);
	const balance = onChain?.balance ?? 0n;
	const deficit = onChain?.deficit ?? 0n;
	if (ledgerBalance === balance && ledgerDeficit === deficit)
		return { kind: "agrees" };
	const synced =
		ledger.lastSyncedBlock === null
			? undefined
			: BigInt(ledger.lastSyncedBlock);
	return {
		kind: "differs",
		ledgerBalance,
		ledgerDeficit,
		lag:
			synced === undefined || readAt === undefined
				? undefined
				: readAt - synced,
	};
}
