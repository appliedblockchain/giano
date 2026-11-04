import type { HealthCheck } from "@appliedblockchain/giano-paymaster-sdk";
import type { ChainDrift, DriftEntry } from "./platform-api";
import { tenantPath } from "./router";

type Check = HealthCheck & { links?: { to: string; label: string }[] };

/**
 * Health's Registry and chain group from wallet-api's drift (B5, D10): the same three questions
 * the console used to answer itself, from the comparison wallet-api makes where the watcher's block
 * is known. Reported as warnings, as drift is everywhere: someone decides what to do about it.
 */
export function driftChecks(
	drift: ChainDrift,
	money: (wei: bigint) => string,
): Check[] {
	const of = <K extends DriftEntry["kind"]>(kind: K) =>
		drift.entries.filter(
			(entry): entry is Extract<DriftEntry, { kind: K }> => entry.kind === kind,
		);
	const links = (entries: { tenantId: string; slug?: string }[]) =>
		entries.slice(0, 5).map((entry) => ({
			to: tenantPath(entry.slug ?? entry.tenantId),
			label: entry.slug ?? entry.tenantId,
		}));
	const at = `as wallet-api compared at ${new Date(drift.checkedAt).toLocaleTimeString()}`;

	const unknown = of("unknown-tenant");
	const enabled = of("enabled-state");
	const ledger = [...of("ledger-balance"), ...of("withdraw-address")];
	return [
		unknown.length === 0
			? {
					id: "registry-rows",
					level: "ok",
					label: "Every on-chain tenant has a registry row",
					detail: at,
				}
			: {
					id: "registry-rows",
					level: "warn",
					label: "On-chain tenants with no registry row",
					detail: `${unknown.length} tenant${unknown.length === 1 ? " is" : "s are"} on this paymaster but unknown to wallet-api: ${unknown.map((entry) => `${entry.tenantId} (${entry.enabledOnChain ? "enabled" : "disabled"}, ${money(BigInt(entry.balanceWei))})`).join("; ")}`,
					remedy:
						"Create the tenant in wallet-api with its id, or confirm it belongs to another deployment.",
				},
		enabled.length === 0
			? {
					id: "drift-enabled",
					level: "ok",
					label: "On-chain state matches the registry",
					detail: `active tenants enabled, suspended and deleted ones disabled, ${at}`,
				}
			: {
					id: "drift-enabled",
					level: "warn",
					label: "On-chain state differs from the registry",
					detail: enabled
						.map(
							(entry) =>
								`${entry.slug} is ${entry.registryStatus} in the registry and ${entry.enabledOnChain ? "enabled" : "disabled"} on chain`,
						)
						.join("; "),
					remedy:
						"Finish the step: disable a suspended or deleted tenant on chain, or enable an active one, from its page.",
					links: links(enabled),
				},
		ledger.length === 0 && drift.unchecked.length === 0
			? {
					id: "ledger",
					level: "ok",
					label: "wallet-api's ledger matches the chain",
					detail: `at the block the ledger describes, ${at}`,
				}
			: {
					id: "ledger",
					level: "warn",
					label:
						ledger.length > 0
							? "wallet-api's ledger differs from the chain"
							: "wallet-api's ledger could not be compared for every tenant",
					detail: [
						...ledger.map((entry) =>
							entry.kind === "ledger-balance"
								? `${entry.slug}: ledger ${money(BigInt(entry.ledger.balanceWei))}, chain ${money(BigInt(entry.chain.balanceWei))} at block ${entry.atBlock}${entry.ledger.deficitWei !== entry.chain.deficitWei ? ` (deficit ${money(BigInt(entry.ledger.deficitWei))} against ${money(BigInt(entry.chain.deficitWei))})` : ""}`
								: `${entry.slug}: ledger withdraws to ${entry.ledger}, the chain to ${entry.chain} at block ${entry.atBlock}`,
						),
						...(drift.unchecked.length > 0
							? [
									`${drift.unchecked.length} tenant(s) could not be read at the ledger's block, so were not compared`,
								]
							: []),
					].join("; "),
					remedy:
						"The ledger disagrees with the chain at a block the watcher has passed, so this is not lag: check wallet-api's paymaster watcher.",
					links: links(ledger),
				},
	];
}
