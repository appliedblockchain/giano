import { eq, inArray } from "drizzle-orm";
import type { Address, Hex } from "viem";
import type { Db } from "../db/index.js";
import { paymasterState, paymasterTenants, tenants } from "../db/schema.js";
import type { PaymasterReader } from "./paymaster-contract.js";

/**
 * Drift (B5, specs/PLATFORM-ADMIN-SPECS.md §5, openspec tenant-chain-drift): where wallet-api's
 * records and a paymaster disagree. Computed per chain at the end of each watcher pass, before the
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

/**
 * Every drifted tenant on one chain's paymaster. Reads the roster at the head, the registry and the
 * ledger, and the chain again at each ledger row's block: the later of the watcher's cursor (every
 * event up to it is in the ledger) and the row's own block (a reconcile writes the head).
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

	const entries: DriftEntry[] = [];
	const unchecked: string[] = [];
	for (const [index, onChain] of roster.entries()) {
		const tenantId = uuids[index];
		const row = ledgerById.get(tenantId);
		const ledgerRow: LedgerRow | undefined = row
			? {
					balanceWei: BigInt(row.balanceWei),
					deficitWei: BigInt(row.deficitWei),
					withdrawAddress: row.withdrawAddress,
					lastSyncedBlock: row.lastSyncedBlock,
				}
			: undefined;
		const block =
			ledgerRow?.lastSyncedBlock === null || ledgerRow === undefined
				? cursor
				: cursor !== null && cursor > ledgerRow.lastSyncedBlock
					? cursor
					: ledgerRow.lastSyncedBlock;
		let atLedgerBlock: { block: bigint; chain: ChainTenant } | undefined;
		if (ledgerRow && block !== null) {
			try {
				atLedgerBlock = {
					block,
					chain: await paymaster.tenantAt(onChain.tenantId, block),
				};
			} catch {
				// A node without that block's state cannot settle it either way: say so, do not guess.
				unchecked.push(tenantId);
			}
		}
		entries.push(
			...tenantDrift({
				tenantId,
				onChain,
				registry: registryById.get(tenantId),
				ledger: ledgerRow,
				atLedgerBlock,
			}),
		);
	}
	return { chainId, checkedAt: new Date(), entries, unchecked };
}

/** The latest drift per chain, kept in memory by whichever replica runs that chain's watcher. */
export function createDriftStore() {
	const latest = new Map<number, ChainDrift>();
	return {
		set: (drift: ChainDrift) => latest.set(drift.chainId, drift),
		get: (chainId: number) => latest.get(chainId),
	};
}

export type DriftStore = ReturnType<typeof createDriftStore>;
