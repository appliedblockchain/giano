/**
 * The inputs every deterministic address is derived from: one deployer EOA per network class, and
 * the labels. A contract's expected address on a chain is CREATE3(the chain's class deployer, its
 * label) (deploy/create3.ts), so every chain in a class shares one set of addresses, and a chain
 * profile can still override single contracts (deploy/profiles.ts).
 */
import { type Address, getAddress } from "viem";
import { ENTRY_POINT_ADDRESS } from "../entrypoint";
import type { ReleaseContractName } from "../release-fingerprints";

/** A chain's network class. Local chains (31337, 31338) are `local`; a profile declares the rest. */
export type NetworkClass = "mainnet" | "testnet" | "local";

/** The classes a chain profile may declare. */
export const PROFILE_NETWORKS = ["mainnet", "testnet"] as const;

/**
 * The canonical deployer of each network class: the EOA that owns every CREATE3 salt on that
 * class's chains. Two independent development-team keys, held in 1Password and outside ABIP-8
 * scope (docs/key-ceremony.md), so a compromised testnet key never touches mainnet.
 *
 * `null` means not chosen yet: the deploy tooling still plans, but refuses to sign for that class.
 * Setting one changes no local-chain address: local chains always use `local`.
 *
 * `local` is a fixed placeholder with no key. It is only ever impersonated (anvil), and it never
 * changes, so the devnet, the e2e state and CI do not move when a real deployer is set.
 */
export const DEPLOYERS: {
	readonly mainnet: Address | null;
	readonly testnet: Address | null;
	readonly local: Address;
} = checkDeployers({
	mainnet: null,
	testnet: null,
	local: getAddress("0x000000000000000000000000000000000000dEaD"),
});

/** Refuses a configuration that would let one key adopt both classes. Exported for tests. */
export function checkDeployers<
	T extends {
		mainnet: Address | null;
		testnet: Address | null;
		local: Address;
	},
>(deployers: T): T {
	const set = [deployers.mainnet, deployers.testnet, deployers.local]
		.filter((a): a is Address => a !== null)
		.map((a) => getAddress(a));
	if (new Set(set).size !== set.length)
		throw new Error(
			"deploy/config.ts: the mainnet, testnet and local deployers must be three different addresses",
		);
	return deployers;
}

/**
 * Names the stand-in deployer of a rehearsal: a run on an anvil fork of a public chain that walks the
 * real deployment path before the canonical deployer exists (deploy/contracts/README.md,
 * "Rehearsal"). Accepted only once {@link activateRehearsal} has seen the RPC report a fork.
 */
export const REHEARSAL_DEPLOYER_ENV = "GIANO_REHEARSAL_DEPLOYER";

let rehearsalDeployer: Address | null = null;

/** Whether this process was asked to rehearse. Nothing is active until {@link activateRehearsal}. */
export function rehearsalRequested(
	env: NodeJS.ProcessEnv = process.env,
): boolean {
	return Boolean(env[REHEARSAL_DEPLOYER_ENV]?.trim());
}

/** The active rehearsal's stand-in deployer, or null outside a rehearsal. */
export function rehearsalDeployerAddress(): Address | null {
	return rehearsalDeployer;
}

/**
 * Anything with an EIP-1193 `request`: a viem client, or an adapter around another library's
 * provider. Typed loosely because viem types `request` per method and has no `anvil_nodeInfo`.
 */
export type RpcRequester = { request: unknown };

/** The fork source an anvil node reports, or null for a node that is not a fork or not anvil. */
export async function forkUrlOf(client: RpcRequester): Promise<string | null> {
	try {
		const request = client.request as (args: {
			method: string;
			params?: unknown;
		}) => Promise<unknown>;
		const info = (await request({ method: "anvil_nodeInfo" })) as {
			forkConfig?: { forkUrl?: string | null };
		} | null;
		return info?.forkConfig?.forkUrl || null;
	} catch {
		// A public RPC has no anvil_ namespace at all.
		return null;
	}
}

/**
 * Turns the rehearsal on when {@link REHEARSAL_DEPLOYER_ENV} is set, after checking that `client` is
 * an anvil fork. From then on the stand-in answers for every non-local class's canonical deployer.
 * Refuses the variable on any RPC that is not a fork, so it can never place contracts on a real chain.
 * Returns the stand-in, or null when no rehearsal was asked for.
 */
export async function activateRehearsal(
	client: RpcRequester,
	env: NodeJS.ProcessEnv = process.env,
): Promise<Address | null> {
	const raw = env[REHEARSAL_DEPLOYER_ENV]?.trim();
	if (!raw) return null;
	let deployer: Address;
	try {
		deployer = getAddress(raw);
	} catch {
		throw new Error(`${REHEARSAL_DEPLOYER_ENV} is not an address`);
	}
	if ((await forkUrlOf(client)) === null)
		throw new Error(
			`${REHEARSAL_DEPLOYER_ENV} is accepted only on an anvil fork, and this RPC is not one. Unset it for a real deployment.`,
		);
	if (
		[DEPLOYERS.local, DEPLOYERS.mainnet, DEPLOYERS.testnet].some(
			(d) => d !== null && getAddress(d) === deployer,
		)
	)
		throw new Error(
			`${REHEARSAL_DEPLOYER_ENV} must be a throwaway address, not a configured deployer`,
		);
	rehearsalDeployer = deployer;
	return deployer;
}

/** Ends a rehearsal in this process. For tests. */
export function resetRehearsal(): void {
	rehearsalDeployer = null;
}

/**
 * The canonical deployer of `network`, or null when it is not configured yet. During a rehearsal, the
 * stand-in answers for every non-local class.
 */
export function classDeployer(network: NetworkClass): Address | null {
	if (network !== "local" && rehearsalDeployer) return rehearsalDeployer;
	return DEPLOYERS[network];
}

/**
 * Fixed labels: one per address that something else is derived from or that people send funds to.
 * They never change. A chain adopted later gets the release current at that time under these same
 * labels, so a user's wallet address (factory + implementation + owners) is the same on every
 * chain of a class. Different chains may hold different releases at one address; the release
 * fingerprints (release-fingerprints.ts) say which.
 */
export const LABELS = {
	walletImplementation: "giano.wallet.impl",
	factory: "giano.factory",
	paymasterImplementation: "giano.paymaster.impl",
	paymasterProxy: "giano.paymaster.proxy",
	/** Fixtures for local chains and testnets only; never on a production chain. */
	testErc20: "giano.test.erc20",
	testPaymaster: "giano.test.paymaster",
} as const;

export type LabelKey = keyof typeof LABELS;

/**
 * The label of an implementation deployed as an upgrade target on a chain that already has the
 * fixed one, e.g. `giano.paymaster.impl@v2`. Proxies (the paymaster, and every user's account)
 * move to it through UUPS; nothing derived from the fixed labels changes.
 */
export function upgradeLabel(base: string, release: string): string {
	return `${base}@${release}`;
}

/** Chains the deploy CLI treats as local: impersonation and installing CreateX are allowed. */
export const LOCAL_CHAIN_IDS = [31337, 31338] as const;

/** Chains that hold real money: the paymaster timelock is mandatory there (G9 R4). */
export const MAINNET_CHAIN_IDS = [1, 8453] as const;

/**
 * Production chains never carry the test fixtures (R-29). Every mainnet is one, whether or not a
 * profile exists for it yet, plus the testnets the platform serves.
 */
export const PRODUCTION_CHAIN_IDS = [
	...MAINNET_CHAIN_IDS,
	84532,
	11155111,
] as const;

/**
 * Refuses a class a chain on the fixed mainnet list can never have. Without it, `--network testnet`
 * on Ethereum mainnet would skip the R-29 fixture guard and the mainnet deviation gate, and place the
 * testnet class's contracts on a mainnet.
 */
export function assertNetworkClass(
	chainId: number,
	network: NetworkClass,
): void {
	if (
		network !== "mainnet" &&
		(MAINNET_CHAIN_IDS as readonly number[]).includes(chainId)
	)
		throw new Error(
			`chain ${chainId} is a mainnet (MAINNET_CHAIN_IDS in deploy/config.ts); it can never be treated as ${network}`,
		);
}

/** G9 R4: a chain on the fixed mainnet list, or any chain declared `mainnet` (by its profile or record). */
export function isMainnetChain(
	chainId: number,
	network?: NetworkClass,
): boolean {
	return (
		network === "mainnet" ||
		(MAINNET_CHAIN_IDS as readonly number[]).includes(chainId)
	);
}

/**
 * R-29: a chain on the fixed list, or any chain declared `mainnet` (by its profile or its record), so
 * that adopting a mainnet protects it without a code change.
 */
export function isProductionChain(
	chainId: number,
	network?: NetworkClass,
): boolean {
	return (
		network === "mainnet" ||
		(PRODUCTION_CHAIN_IDS as readonly number[]).includes(chainId)
	);
}

/**
 * The configured canonical deployers equal to `address`. A deployer only places contracts: it must
 * never hold a role on one, which is what keeps its key outside ABIP-8 (docs/key-ceremony.md).
 */
export function isClassDeployer(address: Address): boolean {
	return [DEPLOYERS.mainnet, DEPLOYERS.testnet, rehearsalDeployer].some(
		(d) => d !== null && getAddress(d) === getAddress(address),
	);
}

/** ERC-4337 EntryPoint v0.9; the wallet implementation hardcodes it. */
export const ENTRY_POINT_V09: Address = ENTRY_POINT_ADDRESS;

/** The release contract deployed under each label, for matching on-chain code (releaseOf). */
export const CONTRACT_OF = {
	walletImplementation: "GianoSmartWallet",
	factory: "GianoSmartWalletFactory",
	paymasterImplementation: "GianoPaymaster",
	paymasterProxy: "ERC1967Proxy",
	testErc20: "PrivateERC20",
	testPaymaster: "PermissivePaymaster",
} as const satisfies Record<LabelKey, ReleaseContractName>;

/**
 * Contracts a chain profile may override (deploy/profiles.ts `addresses`): the core contracts. The
 * timelock is not one: it is deployed with plain CREATE (`deploy:cli timelock`), has no deterministic
 * address, and its address lives in the profile's `timelock.address` alone.
 */
export const OVERRIDE_KEYS = [
	"walletImplementation",
	"factory",
	"paymasterImplementation",
	"paymasterProxy",
] as const;
export type OverrideKey = (typeof OVERRIDE_KEYS)[number];

/**
 * An RPC URL as it may be printed: scheme and host only. A provider key can sit in the path, the
 * query or the credentials (`https://node.provider.com/<key>`), and output reaches terminals, CI and
 * Job logs.
 */
export function redactRpcUrl(url: string): string {
	try {
		return new URL(url).origin;
	} catch {
		return "(unparseable RPC URL)";
	}
}
