import { eq, inArray } from "drizzle-orm";
import type { Address, Hex } from "viem";
import type { Db } from "../db/index.js";
import { paymasterState, paymasterTenants, tenants } from "../db/schema.js";
import type { PaymasterReader } from "./paymaster-contract.js";

/**
 * Drift (B5, specs/PLATFORM-ADMIN-SPECS.md §5, openspec tenant-chain-drift): where wallet-api's
 * records and a paymaster disagree. Computed per chain before each reconcile (every
 * PAYMASTER_RECONCILE_INTERVAL_MS), by the replica that runs that chain's watcher, before the
 * reconcile overwrites the ledger with the chain, and kept in memory with its time (D14).
 *
 * The ledger is checked at the block it describes, never at the head: a watcher that has not yet
 * reached the block that changed a balance is behind, not wrong.
 */

export type DriftEntry =
	| {
			/** On the paymaster's roster, with no registry row: another deployment's, or a registration whose tenant was never created. */
			kind: "unknown-tenant";
			tenantId: string;
			enabledOnChain: boolean;
			balanceWei: string;
	  }
	| {
			/** Active and disabled on chain; or suspended or deleted and enabled on chain. */
			kind: "enabled-state";
			tenantId: string;
			slug: string;
			registryStatus: string;
			enabledOnChain: boolean;
	  }
	| {
			/**
			 * The chain holds a balance or a deficit for a registry tenant, and wallet-api's ledger has no
			 * row for it: events before the registry row existed made none, and the reconcile reads only
			 * tenants it already has.
			 */
			kind: "no-ledger";
			tenantId: string;
			slug: string;
			chain: { balanceWei: string; deficitWei: string };
	  }
	| {
			kind: "ledger-balance";
			tenantId: string;
			slug: string;
			atBlock: string;
			ledger: { balanceWei: string; deficitWei: string };
			chain: { balanceWei: string; deficitWei: string };
	  }
	| {
			kind: "withdraw-address";
			tenantId: string;
			slug: string;
			atBlock: string;
			ledger: string;
			chain: string;
	  };

export type ChainDrift = {
	chainId: number;
	checkedAt: Date;
	entries: DriftEntry[];
	/** Tenants the chain could not be read for at the ledger's block, so were not compared. */
	unchecked: string[];
};

type RegistryRow = { slug: string; status: string };
type LedgerRow = {
	balanceWei: bigint;
	deficitWei: bigint;
	withdrawAddress: string | null;
	lastSyncedBlock: bigint | null;
};
type ChainTenant = {
	registered: boolean;
	enabled: boolean;
	withdrawAddress: Address;
	balanceWei: bigint;
	deficitWei: bigint;
};

/**
 * One tenant's drift, from what the chain says at the head (`onChain`), the registry, the ledger,
 * and what the chain said at the block the ledger describes (`atLedgerBlock`). Pure, so every rule
 * is tested without a chain.
 */
export function tenantDrift(args: {
	tenantId: string;
	onChain: ChainTenant;
	registry: RegistryRow | undefined;
	ledger: LedgerRow | undefined;
	atLedgerBlock: { block: bigint; chain: ChainTenant } | undefined;
}): DriftEntry[] {
	const { tenantId, onChain, registry, ledger, atLedgerBlock } = args;
	// Not registered is a step not yet taken, never drift.
	if (!onChain.registered) return [];
	if (!registry)
		return [
			{
				kind: "unknown-tenant",
				tenantId,
				enabledOnChain: onChain.enabled,
				balanceWei: onChain.balanceWei.toString(),
			},
		];
	const entries: DriftEntry[] = [];
	const shouldBeEnabled = registry.status === "active";
	if (onChain.enabled !== shouldBeEnabled)
		entries.push({
			kind: "enabled-state",
			tenantId,
			slug: registry.slug,
			registryStatus: registry.status,
			enabledOnChain: onChain.enabled,
		});
	if (!ledger && (onChain.balanceWei > 0n || onChain.deficitWei > 0n))
		entries.push({
			kind: "no-ledger",
			tenantId,
			slug: registry.slug,
			chain: {
				balanceWei: onChain.balanceWei.toString(),
				deficitWei: onChain.deficitWei.toString(),
			},
		});
	if (ledger && atLedgerBlock) {
		const { block, chain } = atLedgerBlock;
		if (
			ledger.balanceWei !== chain.balanceWei ||
			ledger.deficitWei !== chain.deficitWei
		)
			entries.push({
				kind: "ledger-balance",
				tenantId,
				slug: registry.slug,
				atBlock: block.toString(),
				ledger: {
					balanceWei: ledger.balanceWei.toString(),
					deficitWei: ledger.deficitWei.toString(),
				},
				chain: {
					balanceWei: chain.balanceWei.toString(),
					deficitWei: chain.deficitWei.toString(),
				},
			});
		if (
			ledger.withdrawAddress &&
			ledger.withdrawAddress.toLowerCase() !==
				chain.withdrawAddress.toLowerCase()
		)
			entries.push({
				kind: "withdraw-address",
				tenantId,
				slug: registry.slug,
				atBlock: block.toString(),
				ledger: ledger.withdrawAddress,
				chain: chain.withdrawAddress,
			});
	}
	return entries;
}

/** The 16-byte id the contract keys on → the registry's uuid. */
const toUuid = (id: Hex) => {
	const hex = id.slice(2).toLowerCase();
	return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
};

/** How many tenants are read at a past block at once: bounded, so a large roster does not burst the node. */
const DRIFT_READ_CONCURRENCY = 5;

/**
 * The block a ledger row describes: the later of the watcher's cursor (every event up to it is in
 * the ledger) and the row's own block (a reconcile writes the head). Undefined for a row the watcher
 * has never synced: it holds no balance yet, so it is not compared.
 */
export function ledgerBlock(
	cursor: bigint | null,
	rowBlock: bigint | null,
): bigint | undefined {
	if (rowBlock === null) return undefined;
	return cursor !== null && cursor > rowBlock ? cursor : rowBlock;
}

/**
 * Every drifted tenant on one chain's paymaster. Reads the roster at the head, the registry and the
 * ledger, and the chain again at each ledger row's block ({@link ledgerBlock}), a few tenants at a
 * time.
 */
export async function computeDrift(options: {
	db: Db;
	chainId: number;
	paymaster: Pick<PaymasterReader, "roster" | "tenantAt">;
}): Promise<ChainDrift> {
	const { db, chainId, paymaster } = options;
	const roster = await paymaster.roster();
	const uuids = roster.map((entry) => toUuid(entry.tenantId));
	const [registry, ledger, [state]] = await Promise.all([
		uuids.length > 0
			? db
					.select({
						id: tenants.id,
						slug: tenants.slug,
						status: tenants.status,
					})
					.from(tenants)
					.where(inArray(tenants.id, uuids))
			: Promise.resolve([]),
		db
			.select()
			.from(paymasterTenants)
			.where(eq(paymasterTenants.chainId, chainId)),
		db
			.select({ cursor: paymasterState.lastSyncedBlock })
			.from(paymasterState)
			.where(eq(paymasterState.chainId, chainId)),
	]);
	const registryById = new Map(registry.map((row) => [row.id, row]));
	const ledgerById = new Map(ledger.map((row) => [row.tenantId, row]));
	const cursor = state?.cursor ?? null;

	const perTenant: { entries: DriftEntry[]; unchecked: boolean }[] = [];
	const compare = async (index: number) => {
		const onChain = roster[index];
		const tenantId = uuids[index];
		const registryRow = registryById.get(tenantId);
		const row = ledgerById.get(tenantId);
		const ledgerRow: LedgerRow | undefined = row
			? {
					balanceWei: BigInt(row.balanceWei),
					deficitWei: BigInt(row.deficitWei),
					withdrawAddress: row.withdrawAddress,
					lastSyncedBlock: row.lastSyncedBlock,
				}
			: undefined;
		const block = ledgerRow
			? ledgerBlock(cursor, ledgerRow.lastSyncedBlock)
			: undefined;
		let atLedgerBlock: { block: bigint; chain: ChainTenant } | undefined;
		// A row not yet synced, or a chain unreadable at its block, cannot settle the ledger either
		// way: say so, do not guess. The rules that need no past block still apply.
		let notCompared = registryRow !== undefined && ledgerRow !== undefined;
		if (ledgerRow && block !== undefined && registryRow) {
			try {
				atLedgerBlock = {
					block,
					chain: await paymaster.tenantAt(onChain.tenantId, block),
				};
				notCompared = false;
			} catch {
				// A node without that block's state.
			}
		}
		perTenant[index] = {
			entries: tenantDrift({
				tenantId,
				onChain,
				registry: registryRow,
				ledger: ledgerRow,
				atLedgerBlock,
			}),
			unchecked: notCompared && onChain.registered,
		};
	};
	let next = 0;
	await Promise.all(
		Array.from(
			{ length: Math.min(DRIFT_READ_CONCURRENCY, roster.length) },
			async () => {
				for (let index = next++; index < roster.length; index = next++)
					await compare(index);
			},
		),
	);
	return {
		chainId,
		checkedAt: new Date(),
		entries: perTenant.flatMap((tenant) => tenant.entries),
		unchecked: uuids.filter((_, index) => perTenant[index].unchecked),
	};
}

/** Drift entries that are drift in this deployment's own records: not another deployment's tenants. */
export const isOwnDrift = (entry: DriftEntry) =>
	entry.kind !== "unknown-tenant";

/** How long a result computed on demand (by a replica without the watcher) is reused. */
export const DRIFT_REUSE_MS = 15_000;

/**
 * The latest drift per chain, in memory. The watcher's replica sets each pass's result. A replica
 * without the watcher computes on demand, reuses that for {@link DRIFT_REUSE_MS}, and shares a
 * computation in flight, so a console refreshing every few seconds does not read the whole roster
 * each time.
 *
 * The watcher's result is served only while it is fresh (`maxAgeMs`): one older is a watcher that
 * stopped or lost its lock, and is computed again rather than served as current.
 */
export function createDriftStore() {
	const latest = new Map<number, ChainDrift>();
	const recent = new Map<number, ChainDrift>();
	const inFlight = new Map<number, Promise<ChainDrift>>();
	const youngerThan = (drift: ChainDrift | undefined, ms: number) =>
		drift && Date.now() - drift.checkedAt.getTime() <= ms ? drift : undefined;
	return {
		/** A watcher pass's result. */
		set: (drift: ChainDrift) => latest.set(drift.chainId, drift),
		/** Forget a chain's results: the watcher lost its lock, or its drift pass failed. */
		clear: (chainId: number) => {
			latest.delete(chainId);
			recent.delete(chainId);
		},
		/** The watcher's result, if it is no older than `maxAgeMs`. */
		get: (chainId: number, maxAgeMs: number) =>
			youngerThan(latest.get(chainId), maxAgeMs),
		/** The watcher's result if fresh, else a recent or shared computation, else a new one. */
		fresh(
			chainId: number,
			maxAgeMs: number,
			compute: () => Promise<ChainDrift>,
		): Promise<ChainDrift> {
			const stored =
				youngerThan(latest.get(chainId), maxAgeMs) ??
				youngerThan(recent.get(chainId), DRIFT_REUSE_MS);
			if (stored) return Promise.resolve(stored);
			const running = inFlight.get(chainId);
			if (running) return running;
			const started = compute()
				.then((drift) => {
					recent.set(chainId, drift);
					return drift;
				})
				.finally(() => inFlight.delete(chainId));
			inFlight.set(chainId, started);
			return started;
		},
	};
}

export type DriftStore = ReturnType<typeof createDriftStore>;
