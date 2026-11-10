/**
 * Runtime configuration, fetched from `/config.json` before the first render.
 *
 * Deliberately not build-time `VITE_` variables: one published image has to serve every
 * deployment, and a console baked to a single chain and paymaster address would need a rebuild per
 * environment — which is exactly when someone points the production console at a devnet by
 * accident. The container renders the same file from environment variables at boot.
 *
 * The file declares a *list* of deployments the console may administer. That list is the whole of
 * what it can reach: an operator picks between environments someone deliberately configured, and
 * cannot point the console at an arbitrary chain by typing into it. Which is the useful half of
 * the safety property — switching between known environments is routine; reaching an unknown one
 * by accident is what must stay impossible.
 */
import {
	TIMELOCKED_FUNCTION_NAMES,
	type TimelockDelays,
} from "@appliedblockchain/giano-paymaster-sdk";

/**
 * One paymaster deployment the console can administer.
 *
 * `chainId`, `name`, `rpcUrl` and `sponsorshipPaymaster` are spelled exactly as the chain
 * descriptor in `packages/contracts/chains.ts` spells them, which is what lets a deployment hand
 * this file the same array `wallet-api` reads as `GIANO_CHAINS` rather than authoring a second one
 * that has to be kept in step. A descriptor's remaining fields are for submitting operations, not
 * administering a paymaster, and are dropped before they reach the browser (§14.6).
 */
export type Deployment = {
	/** How an operator tells this environment apart. Shown in the header. */
	name: string;
	chainId: number;
	rpcUrl: string;
	/**
	 * The paymaster proxy.
	 *
	 * Optional in the type because the SDK can resolve it from the contracts registry — but no chain
	 * in that registry currently declares a `sponsorshipPaymaster`, so in practice this must be set.
	 * Leaving it out fails loudly rather than silently reading the wrong contract.
	 */
	sponsorshipPaymaster?: `0x${string}`;
	/**
	 * The paymaster's GianoTimelock (G9), when it has been handed off to one.
	 *
	 * Optional: a devnet, where one key holds every role, has none. Set, the console reads its delays
	 * and pending operations in the Timelock tab, and a timelocked action the connected wallet cannot
	 * send (a fee, a withdrawal address, a role change) opens a proposal for the timelock instead of
	 * offering a transaction that would revert. The paymaster cannot name its timelock — a role holder
	 * is just an address — so it is configured beside it.
	 */
	timelockAddress?: `0x${string}`;
	/**
	 * The timelock delays this chain publishes, in seconds: its profile's `timelock.delays`
	 * (deploy/chains/*.json). Set, Health fails a delay below its published value, as giano-doctor
	 * does; unset, Health says the delays were not compared. Every name is required: a delay left
	 * out would be one Health says is "at or above the published value" without comparing it.
	 */
	timelockDelays?: TimelockDelays;
	/**
	 * Where a *wallet* should reach this chain, when that is not where the console reads.
	 *
	 * The console reads through its own origin — `rpcUrl` is normally `/rpc/<chainId>`, a proxy that
	 * keeps a keyed provider endpoint server-side. A wallet asked to add the network has to dial it
	 * itself, from outside this page, and cannot use either a path on this origin or, in MetaMask's
	 * case, anything that is not HTTPS or literal localhost. So the address to hand a wallet is
	 * stated rather than derived: deriving it from `rpcUrl` would mean publishing the keyed endpoint
	 * to every operator's wallet, which is the thing the proxy exists to prevent.
	 *
	 * Optional, and only used when the wallet does not already know the chain. Unset, the console
	 * offers `rpcUrl` and reports what the wallet says if it refuses.
	 */
	walletRpcUrl?: string;
	/**
	 * Seconds between automatic refreshes. 0 disables polling.
	 *
	 * The one field a chain descriptor has no opinion about — how often a console polls is not a
	 * property of the chain — so it defaults rather than being required of an array authored for
	 * `wallet-api`.
	 */
	refreshSeconds: number;
	/**
	 * What amounts on this chain are denominated in, as the chain descriptor spells it. Absent means
	 * ETH with 18 decimals, as it does for every other Giano service reading the same descriptor.
	 */
	nativeCurrency: NativeCurrency;
	/**
	 * A block explorer for this chain, e.g. `https://sepolia.basescan.org`. Set, every transaction
	 * hash and address links to it; unset — a devnet has none — they are shown in full and copyable.
	 */
	explorerUrl?: string;
	/**
	 * Names for addresses the chain cannot name itself, keyed by lowercase address (openspec D9).
	 *
	 * A timelock cannot list who holds its roles, so the Safe that proposes is invisible unless it is
	 * written down here. Every configured address is also a candidate the console checks role
	 * membership against, and one with `kind: "safe"` has its threshold read from the Safe.
	 */
	addresses: Readonly<Record<string, KnownAddress>>;
};

export type NativeCurrency = { symbol: string; decimals: number };

export type KnownAddress = { label: string; kind?: "safe" };

export type AdminConfig = {
	deployments: readonly Deployment[];
	/**
	 * Whether this console can reach wallet-api's platform tier through its own `/api` proxy — true
	 * exactly when the container was given GIANO_WALLET_API_UPSTREAM. False hides the Platform area
	 * entirely, which is what every deployment that sets nothing new gets.
	 */
	platformApi: boolean;
};

/**
 * The file as it actually arrives, before validation.
 *
 * Loosely typed because the container renders it from environment variables: an unset optional
 * variable substitutes to `""`, not to an absent key, and typing it as the validated shape would
 * let those empty strings through as real addresses.
 */
type RawDeployment = {
	name?: string;
	chainId?: number | string;
	rpcUrl?: string;
	walletRpcUrl?: string;
	sponsorshipPaymaster?: string;
	timelockAddress?: string;
	timelockDelays?: Record<string, unknown>;
	refreshSeconds?: number | string | null;
	nativeCurrency?: { symbol?: string; decimals?: number };
	explorerUrl?: string;
	addresses?: Record<string, { label?: string; kind?: string }>;
};

type RawAdminConfig = RawDeployment & {
	deployments?: RawDeployment[];
	/** Accepted at the top level for the single-deployment shape. */
	environmentLabel?: string;
	platformApi?: boolean;
};

let config: AdminConfig | undefined;

const DEFAULT_REFRESH_SECONDS = 15;

const ETH: NativeCurrency = { symbol: "ETH", decimals: 18 };

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;

function toDeployment(
	raw: RawDeployment,
	fallbackName: string,
	index: number,
): Deployment {
	const chainId = Number(raw.chainId);
	if (!chainId || Number.isNaN(chainId))
		throw new Error(
			`deployment ${index + 1} (${raw.name ?? fallbackName}) has no chainId`,
		);
	if (!raw.rpcUrl)
		throw new Error(
			`deployment ${index + 1} (${raw.name ?? fallbackName}) has no rpcUrl`,
		);
	const where = `deployment ${index + 1} (${raw.name ?? fallbackName})`;
	if (raw.timelockAddress && !ADDRESS.test(raw.timelockAddress))
		throw new Error(
			`${where} has a timelockAddress that is not an address: ${raw.timelockAddress}`,
		);
	const refreshSeconds = toRefreshSeconds(raw.refreshSeconds, where);

	return {
		name: raw.name || fallbackName || `chain ${chainId}`,
		chainId,
		rpcUrl: raw.rpcUrl,
		walletRpcUrl: raw.walletRpcUrl || undefined,
		sponsorshipPaymaster: raw.sponsorshipPaymaster
			? (raw.sponsorshipPaymaster as `0x${string}`)
			: undefined,
		timelockAddress: raw.timelockAddress
			? (raw.timelockAddress as `0x${string}`)
			: undefined,
		timelockDelays: toTimelockDelays(raw.timelockDelays, where),
		refreshSeconds,
		nativeCurrency: toNativeCurrency(raw.nativeCurrency, where),
		explorerUrl: toExplorerUrl(raw.explorerUrl, where),
		addresses: toAddresses(raw.addresses, where),
	};
}

const DELAY_NAMES: readonly (keyof TimelockDelays)[] = [
	"minDelay",
	...TIMELOCKED_FUNCTION_NAMES,
];

export function toTimelockDelays(
	raw: RawDeployment["timelockDelays"],
	where: string,
): TimelockDelays | undefined {
	if (!raw || Object.keys(raw).length === 0) return undefined;
	// All or none, as deploy/cli.ts requires of a profile: a partial list would let a shortened delay
	// it leaves out pass as "at or above the published values".
	const missing = DELAY_NAMES.filter((name) => !(name in raw));
	if (missing.length > 0)
		throw new Error(
			`${where} has timelockDelays without ${missing.join(", ")}; give every delay the chain's profile publishes (deploy/chains/*.json), or none`,
		);
	const delays: Partial<TimelockDelays> = {};
	for (const [name, value] of Object.entries(raw)) {
		if (!DELAY_NAMES.includes(name as keyof TimelockDelays))
			throw new Error(
				`${where} has a timelock delay for "${name}"; the names are ${DELAY_NAMES.join(", ")}`,
			);
		if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0)
			throw new Error(
				`${where} has a ${name} delay that is not a whole number of seconds: ${JSON.stringify(value)}`,
			);
		delays[name as keyof TimelockDelays] = value;
	}
	return delays as TimelockDelays;
}

function toNativeCurrency(
	raw: RawDeployment["nativeCurrency"],
	where: string,
): NativeCurrency {
	if (!raw) return ETH;
	const { symbol, decimals } = raw;
	if (
		!symbol ||
		typeof decimals !== "number" ||
		!Number.isInteger(decimals) ||
		decimals < 0 ||
		decimals > 36
	)
		throw new Error(
			`${where} has a nativeCurrency that needs a symbol and whole-number decimals: ${JSON.stringify(raw)}`,
		);
	return { symbol, decimals };
}

/** A day: anything longer is not polling, and past ~24.8 days `setInterval` overflows and fires at once. */
const MAX_REFRESH_SECONDS = 86_400;

/**
 * 0 (no polling) or a whole number of seconds from 1 to a day; absent or empty means the default.
 * Checked rather than passed through: `Number("15s")` is NaN and `setInterval` reads NaN as 0, `0.001`
 * polls every millisecond, and `Number(" ")` and `Number(null)` are 0, which would turn polling off
 * without a word.
 */
export function toRefreshSeconds(
	raw: number | string | null | undefined,
	where: string,
): number {
	if (raw === undefined || raw === "") return DEFAULT_REFRESH_SECONDS;
	const seconds =
		typeof raw === "number" || (typeof raw === "string" && raw.trim() === raw)
			? Number(raw)
			: Number.NaN;
	if (
		!Number.isInteger(seconds) ||
		seconds < 0 ||
		seconds > MAX_REFRESH_SECONDS
	)
		throw new Error(
			`${where} has a refreshSeconds that is not 0 or a whole number of seconds from 1 to ${MAX_REFRESH_SECONDS}: ${JSON.stringify(raw)}`,
		);
	return seconds;
}

/**
 * HTTPS, or plain HTTP to a local explorer. A link an operator follows to check a transaction is
 * one an attacker on the path would most like to rewrite.
 */
export function toExplorerUrl(
	raw: string | undefined,
	where: string,
): string | undefined {
	if (!raw) return undefined;
	let url: URL;
	try {
		url = new URL(raw);
	} catch {
		throw new Error(`${where} has an explorerUrl that is not a URL: ${raw}`);
	}
	const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
	if (url.protocol !== "https:" && !(url.protocol === "http:" && local))
		throw new Error(
			`${where} has an explorerUrl that is not https (or http on localhost): ${raw}`,
		);
	// Links are built by appending `/tx/<hash>` or `/address/<address>`, which a query or a fragment
	// would swallow.
	if (url.search || url.hash || raw.includes("?") || raw.includes("#"))
		throw new Error(
			`${where} has an explorerUrl with a query or a fragment, which links cannot be appended to: ${raw}`,
		);
	return raw.replace(/\/+$/, "");
}

export function toAddresses(
	raw: RawDeployment["addresses"],
	where: string,
): Record<string, KnownAddress> {
	const addresses: Record<string, KnownAddress> = {};
	for (const [address, entry] of Object.entries(raw ?? {})) {
		if (!ADDRESS.test(address))
			throw new Error(
				`${where} names an address that is not an address: ${address}`,
			);
		if (!entry?.label)
			throw new Error(`${where} names ${address} without a label`);
		if (entry.kind !== undefined && entry.kind !== "safe")
			throw new Error(
				`${where} gives ${address} the kind "${entry.kind}"; the only kind is "safe"`,
			);
		addresses[address.toLowerCase()] = {
			label: entry.label,
			...(entry.kind ? { kind: entry.kind } : {}),
		};
	}
	return addresses;
}

export async function loadAdminConfig(): Promise<AdminConfig> {
	if (config) return config;

	const response = await fetch("/config.json", { cache: "no-store" });
	if (!response.ok)
		throw new Error(`failed to load /config.json: ${response.status}`);
	const raw = (await response.json()) as RawAdminConfig;

	// Two accepted shapes. The single-deployment one is kept because it is what a container
	// rendering one set of environment variables produces, and because most deployments really do
	// administer one chain — making them declare a one-element array would be ceremony.
	const rawDeployments =
		raw.deployments && raw.deployments.length > 0
			? raw.deployments
			: [{ ...raw, name: raw.name ?? raw.environmentLabel }];

	const deployments = rawDeployments.map((entry, index) =>
		toDeployment(entry, entry.name ?? "", index),
	);

	const seen = new Set<string>();
	for (const deployment of deployments) {
		const key = deploymentKey(deployment);
		if (seen.has(key))
			throw new Error(
				`two deployments share chain ${deployment.chainId} and the same paymaster address; give them distinct addresses`,
			);
		seen.add(key);
	}

	config = { deployments, platformApi: raw.platformApi === true };
	return config;
}

/** The loaded config. Throws if called before {@link loadAdminConfig} has resolved. */
export function getAdminConfig(): AdminConfig {
	if (!config) throw new Error("admin config accessed before it was loaded");
	return config;
}

/**
 * A stable identity for a deployment, used to remember the operator's choice.
 *
 * Keyed on chain and address rather than on the name: a name is prose and gets reworded, and a
 * remembered selection that silently moved to a different environment because someone fixed a typo
 * would be worse than not remembering it at all.
 */
export function deploymentKey(deployment: Deployment): string {
	return `${deployment.chainId}:${deployment.sponsorshipPaymaster?.toLowerCase() ?? "registry"}`;
}

const STORAGE_KEY = "giano:paymaster-admin:deployment";

/** The deployment to open with: the one last chosen, when it is still declared, else the first. */
export function initialDeployment(
	deployments: readonly Deployment[],
): Deployment {
	try {
		const remembered = localStorage.getItem(STORAGE_KEY);
		const match = deployments.find(
			(deployment) => deploymentKey(deployment) === remembered,
		);
		if (match) return match;
	} catch {
		// Storage can be unavailable (private mode, blocked cookies). Not remembering is fine.
	}
	return deployments[0];
}

export function rememberDeployment(deployment: Deployment): void {
	try {
		localStorage.setItem(STORAGE_KEY, deploymentKey(deployment));
	} catch {
		// As above — a console that cannot remember the choice still works.
	}
}
