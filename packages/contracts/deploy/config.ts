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

/** The canonical deployer of `network`, or null when it is not configured yet. */
export function classDeployer(network: NetworkClass): Address | null {
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

/** Production chains never carry the test fixtures (R-29). */
export const PRODUCTION_CHAIN_IDS = [8453, 84532, 11155111] as const;

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
 * Contracts a chain profile may override (deploy/profiles.ts `addresses`): the core contracts, and
 * the paymaster's timelock, which is never deterministic (plain CREATE) but is verified the same way.
 */
export const OVERRIDE_KEYS = [
	"walletImplementation",
	"factory",
	"paymasterImplementation",
	"paymasterProxy",
	"timelock",
] as const;
export type OverrideKey = (typeof OVERRIDE_KEYS)[number];
