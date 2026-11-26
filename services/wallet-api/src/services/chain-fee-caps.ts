/**
 * Default relay fee caps per chain (openspec change userop-policy-defaults, design D2).
 *
 * One chain-agnostic cap cannot be right on both Ethereum and Base: their fees differ by three
 * orders of magnitude, so the old 500 gwei default never fired on an L2. Each value here is far
 * above that chain's normal fees, so it fires on a client bug or an attack rather than on
 * congestion. They seed a chain's stored relay policy (chain-policy.ts) the first time wallet-api
 * serves it; from then on the stored value applies, unless a descriptor's `walletApi.policy` cap or a
 * `USEROP_MAX_*_FEE_PER_GAS` env var overrides it. A tenant's overrides apply on top.
 *
 * Local devnets and Silent Data are left out on purpose: whoever runs them sets their fees.
 */

export type FeeCaps = { maxFeePerGas: bigint; maxPriorityFeePerGas: bigint };

const GWEI = 1_000_000_000n;

const OP_STACK_PUBLIC: FeeCaps = {
	maxFeePerGas: 10n * GWEI,
	maxPriorityFeePerGas: 1n * GWEI,
};

export const KNOWN_CHAIN_FEE_CAPS: Readonly<Record<number, FeeCaps>> = {
	1: { maxFeePerGas: 300n * GWEI, maxPriorityFeePerGas: 20n * GWEI },
	// Sepolia's spikes are large and its funds worthless: keep the old ceiling for the fee.
	11155111: { maxFeePerGas: 500n * GWEI, maxPriorityFeePerGas: 50n * GWEI },
	10: OP_STACK_PUBLIC,
	8453: OP_STACK_PUBLIC,
	84532: OP_STACK_PUBLIC,
};

/**
 * The caps for a chain nothing else gives one to: the pre-G6 default. A production deployment
 * refuses to boot rather than use it (config.ts).
 */
export const FALLBACK_FEE_CAPS: FeeCaps = {
	maxFeePerGas: 500n * GWEI,
	maxPriorityFeePerGas: 500n * GWEI,
};
