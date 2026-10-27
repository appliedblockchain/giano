/**
 * The inputs every canonical address is derived from: the deployer EOA and the labels.
 * `pnpm gen:canonical` turns these into canonical.ts, so this file is the one place to change them.
 */
import { type Address, getAddress } from "viem";

/**
 * The EOA that owns every canonical CREATE3 salt (deploy/create3.ts). It is part of every canonical
 * address, so it is permanent: keep its key in a KMS/HSM, use it for nothing else, and never let
 * it be lost — without it no new chain can be given the canonical addresses.
 *
 * ⚠ PLACEHOLDER. No key exists for this address. Local chains impersonate it (`--impersonate`),
 * which is all the devnet, e2e and CI need; the deploy CLI refuses any other chain while this is
 * set. To switch to the real deployer: set its address here, run `pnpm gen:canonical` and
 * regenerate the devnet state (`pnpm -F @appliedblockchain/giano-e2e devnet:generate:all`).
 */
export const CANONICAL_DEPLOYER: Address = getAddress(
	"0x000000000000000000000000000000000000dEaD",
);

/** True while {@link CANONICAL_DEPLOYER} is the placeholder above. */
export const DEPLOYER_IS_PLACEHOLDER =
	CANONICAL_DEPLOYER ===
	getAddress("0x000000000000000000000000000000000000dEaD");

/**
 * Fixed labels: one per address that something else is derived from or that people send funds to.
 * They never change. A chain adopted later gets the release current at that time under these same
 * labels, so a user's wallet address (factory + implementation + owners) is the same on every
 * chain, forever. Different chains may therefore hold different releases at one address; the
 * codehashes in canonical.ts say which.
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
export const ENTRY_POINT_V09: Address =
	"0x433709009B8330FDa32311DF1C2AFA402eD8D009";
