/**
 * giano-doctor's drift check (B5): where wallet-api's URL is safe to send a platform session to, and
 * what each answer from GET /v1/platform/drift means for the run. Pure, so both are tested without
 * a wallet-api.
 */

export type DriftChain =
	| {
			chainId: number;
			checkedAt: string;
			entries: ({ kind: string; tenantId: string; slug?: string } & Record<
				string,
				unknown
			>)[];
			unchecked: string[];
			/** Tenants waiting for registerTenant on this chain; absent from a wallet-api older than it. */
			unregistered?: { tenantId: string; slug: string }[];
	  }
	| { chainId: number; error: string; message: string };

export type DriftLine = {
	level: "ok" | "warn" | "fail" | "info";
	label: string;
	detail: string;
};

/** A drift result older than this is a watcher that stopped: said, not taken as current. */
export const DRIFT_STALE_MS = 10 * 60_000;

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * The drift endpoint under `api`, keeping any path it has (`https://host/api` →
 * `https://host/api/v1/platform/drift`). Refuses anything but https, except on this machine, so a
 * typo does not send the session token in cleartext.
 */
export function driftUrl(api: string): URL {
	const base = new URL(api);
	if (base.protocol !== "https:" && !LOCAL_HOSTS.has(base.hostname))
		throw new Error(
			`the wallet-api URL must be https (http only for localhost): ${base.origin}`,
		);
	if (!base.pathname.endsWith("/")) base.pathname = `${base.pathname}/`;
	return new URL("v1/platform/drift", base);
}

/**
 * What one chain's drift answer means for the run. A tenant another deployment registered on a
 * shared paymaster (`unknown-tenant`) is a warning, as the console shows it: the specs support shared
 * paymasters, and failing on them would fail every run. "No drift" only when every tenant was
 * compared.
 */
export function driftLines(chain: DriftChain, now = Date.now()): DriftLine[] {
	if ("error" in chain)
		return [
			{
				level: "fail",
				label: "read the drift",
				detail: `wallet-api could not compute chain ${chain.chainId}'s drift: ${chain.message}`,
			},
		];
	const lines: DriftLine[] = [];
	const age = now - Date.parse(chain.checkedAt);
	if (age > DRIFT_STALE_MS)
		lines.push({
			level: "warn",
			label: "drift result is old",
			detail: `checked ${chain.checkedAt}, ${Math.round(age / 60_000)} minutes ago: wallet-api's watcher may have stopped`,
		});
	for (const entry of chain.entries) {
		const { kind, tenantId, slug, ...detail } = entry;
		lines.push({
			level: kind === "unknown-tenant" ? "warn" : "fail",
			label: `drift: ${kind}`,
			detail: `${slug ?? tenantId} ${JSON.stringify(detail)}${kind === "unknown-tenant" ? " — another deployment's on a shared paymaster, or a registration whose tenant was never created" : ""}`,
		});
	}
	if (chain.unchecked.length > 0)
		lines.push({
			level: "warn",
			label: "drift: not compared",
			detail: `${chain.unchecked.length} tenant(s) not compared (not yet synced, or unreadable at the ledger's block): ${chain.unchecked.join(", ")}`,
		});
	// Not drift: a tenant with sponsorship switched on that nobody has registered on chain yet, so
	// every one of its sponsorship requests is refused until someone does.
	const unregistered = chain.unregistered ?? [];
	if (unregistered.length > 0)
		lines.push({
			level: "warn",
			label: "not yet sponsorable",
			detail: `${unregistered.length} active tenant(s) have sponsorship on and are not registered on chain ${chain.chainId}'s paymaster (registerTenant): ${unregistered.map((tenant) => tenant.slug).join(", ")}`,
		});
	if (
		!chain.entries.some((entry) => entry.kind !== "unknown-tenant") &&
		chain.unchecked.length === 0
	)
		lines.push({
			level: "ok",
			label: "no drift",
			detail: `checked ${chain.checkedAt}`,
		});
	return lines;
}
