// The chain descriptor — the ONE configuration shape naming a chain a Giano deployment
// serves, carried identically by the wallet origin, the backend and the operator console
// (specs/MULTICHAIN_SPECS.md §3, MC-95). Each consumer validates the same core and extends
// it with what only it needs.

import { z } from "zod";
import { gianoAddresses } from "./addresses";

const addressPattern = /^0x[0-9a-fA-F]{40}$/;

export const chainAddressSchema: z.ZodType<`0x${string}`> = z
	.string()
	.regex(
		addressPattern,
		"must be a 0x-prefixed 20-byte hex address",
	) as z.ZodType<`0x${string}`>;

/**
 * The core every consumer shares. There is deliberately no `default` field: there is no
 * default chain anywhere in the system (MC-11). A dApp always names the chain it wants,
 * and a backend request may omit it only when exactly one chain is configured (MC-53).
 */
// Each schema's shape is spelled out so its type can be read without inference (isolatedDeclarations);
// zod derives the parsed and input types from the shape exactly as it would from the inferred one.
type ChainDescriptorShape = {
	chainId: z.ZodNumber;
	name: z.ZodString;
	rpcUrl: z.ZodString;
	nativeCurrency: z.ZodOptional<
		z.ZodObject<
			{
				symbol: z.ZodString;
				decimals: z.ZodNumber;
				name: z.ZodOptional<z.ZodString>;
			},
			z.core.$strip
		>
	>;
};

export const chainDescriptorSchema: z.ZodObject<
	ChainDescriptorShape,
	z.core.$strip
> = z.object({
	chainId: z.number().int().positive(),
	/** Human-readable, shown to users and operators. Required — MC-81 forbids bare ids in the UI. */
	name: z.string().min(1),
	/** Read path. */
	rpcUrl: z.string().url(),
	/**
	 * What `value` is denominated in on this chain, for anything that shows an amount to a user.
	 * Optional: absent means ETH with 18 decimals, which is what every chain Giano ships with uses.
	 */
	nativeCurrency: z
		.object({
			symbol: z.string().min(1),
			decimals: z.number().int().min(0).max(36),
			name: z.string().min(1).optional(),
		})
		.optional(),
});

export type NativeCurrency = NonNullable<ChainDescriptor["nativeCurrency"]>;

/** The default when a descriptor names no native currency. */
export const DEFAULT_NATIVE_CURRENCY = {
	symbol: "ETH",
	decimals: 18,
	name: "Ether",
} as const;

export type ChainDescriptor = z.infer<typeof chainDescriptorSchema>;

/**
 * A relay allowlist: `"any"` records the choice to allow any address; a list allows only those.
 * An empty list is read as `"any"`, which is what it has always meant; write `"any"` instead.
 */
type ChainAllowlist = z.ZodUnion<
	readonly [z.ZodLiteral<"any">, z.ZodArray<z.ZodType<`0x${string}`>>]
>;

const chainAllowlistSchema: ChainAllowlist = z.union([
	z.literal("any"),
	z.array(chainAddressSchema),
]);

/** Per-chain policy defaults. Address-valued fields are never inherited across chains (MC-61). */
type ChainPolicyShape = {
	maxCallGas: z.ZodOptional<z.ZodString>;
	maxVerificationGas: z.ZodOptional<z.ZodString>;
	maxPreVerificationGas: z.ZodOptional<z.ZodString>;
	maxPaymasterVerificationGas: z.ZodOptional<z.ZodString>;
	maxPaymasterPostOpGas: z.ZodOptional<z.ZodString>;
	maxFeePerGas: z.ZodOptional<z.ZodString>;
	maxPriorityFeePerGas: z.ZodOptional<z.ZodString>;
	allowedTargets: z.ZodOptional<ChainAllowlist>;
	allowedPaymasters: z.ZodOptional<ChainAllowlist>;
};

export const chainPolicySchema: z.ZodObject<ChainPolicyShape, z.core.$strict> =
	z
		.object({
			maxCallGas: z.string().regex(/^\d+$/).optional(),
			maxVerificationGas: z.string().regex(/^\d+$/).optional(),
			// The caps added with G6 must be positive: a cap of 0 refuses every operation that uses it.
			maxPreVerificationGas: z
				.string()
				.regex(/^[1-9]\d*$/)
				.optional(),
			maxPaymasterVerificationGas: z
				.string()
				.regex(/^[1-9]\d*$/)
				.optional(),
			maxPaymasterPostOpGas: z
				.string()
				.regex(/^[1-9]\d*$/)
				.optional(),
			maxFeePerGas: z.string().regex(/^\d+$/).optional(),
			maxPriorityFeePerGas: z.string().regex(/^\d+$/).optional(),
			allowedTargets: chainAllowlistSchema.optional(),
			allowedPaymasters: chainAllowlistSchema.optional(),
		})
		.strict();

export type ChainPolicy = z.infer<typeof chainPolicySchema>;

/**
 * wallet-api's section of a backend chain entry. `factory` and `implementation` (the wallet
 * implementation the factory must clone) default from the contracts registry for `chainId`.
 * `bundlerUrl` defaults to wallet-api's `BUNDLER_BASE_URL` with `/<chainId>` appended; set it for
 * a chain submitted through some other bundler.
 */
type WalletApiChainSectionShape = {
	factory: z.ZodOptional<z.ZodType<`0x${string}`>>;
	implementation: z.ZodOptional<z.ZodType<`0x${string}`>>;
	policy: z.ZodOptional<z.ZodObject<ChainPolicyShape, z.core.$strict>>;
	bundlerUrl: z.ZodOptional<z.ZodString>;
};

export const walletApiChainSectionSchema: z.ZodObject<
	WalletApiChainSectionShape,
	z.core.$strict
> = z
	.object({
		factory: chainAddressSchema.optional(),
		implementation: chainAddressSchema.optional(),
		policy: chainPolicySchema.optional(),
		bundlerUrl: z.string().url().optional(),
	})
	.strict();

export type WalletApiChainSection = z.infer<typeof walletApiChainSectionSchema>;

/** giano-bundler's section of a backend chain entry. */
type BundlerChainSectionShape = {
	enabled: z.ZodDefault<z.ZodBoolean>;
	rpcUrl: z.ZodOptional<z.ZodString>;
	chainType: z.ZodDefault<
		z.ZodEnum<{ auto: "auto"; default: "default"; "op-stack": "op-stack" }>
	>;
	maxBlockRange: z.ZodDefault<z.ZodNumber>;
	stateOverride: z.ZodDefault<z.ZodBoolean>;
};

export const bundlerChainSectionSchema: z.ZodObject<
	BundlerChainSectionShape,
	z.core.$strict
> = z
	.object({
		/** `false`: this bundler does not serve the chain, and wallet-api must name another `bundlerUrl`. */
		enabled: z.boolean().default(true),
		/** Overrides the shared `rpcUrl` for submission and simulation only. */
		rpcUrl: z.string().url().optional(),
		/** `auto` detects an OP-stack chain from its GasPriceOracle predeploy. */
		chainType: z.enum(["auto", "default", "op-stack"]).default("auto"),
		/** Receipt lookback, in blocks, for operations this process did not submit. */
		maxBlockRange: z.number().int().positive().default(2000),
		/**
		 * Set `false` only when the RPC refuses `eth_call` state overrides (Silent Data), so gas
		 * estimation cannot simulate. The bundler then returns fixed limits: verification gas
		 * 1,000,000, call gas 300,000 (1,000,000 at a fee of 0, 0 for empty call data), and paymaster
		 * verification gas 200,000. It keeps the caller's call gas (at least 9,000), and a higher
		 * verification or paymaster verification gas.
		 *
		 * On a chain that charges no gas the fixed limits cost nothing. On a chain that charges gas, the
		 * prefund and wallet-api's maximum charge cover about 1.5 million gas plus pre-verification
		 * gas, so size the paymaster deposit, tenant balances and `maxCostPerTxWei` for that. The
		 * bundler never falls back to fixed limits by itself, so a simulation fault stays an error.
		 */
		stateOverride: z.boolean().default(true),
	})
	.strict();

export type BundlerChainSection = z.infer<typeof bundlerChainSectionSchema>;

/**
 * paymaster-admin's section of a backend chain entry, read by its container entrypoint (which
 * has jq, not this schema): where a wallet should dial to add the network, and how often the
 * console refreshes.
 */
type PaymasterAdminChainSectionShape = {
	walletRpcUrl: z.ZodOptional<z.ZodString>;
	refreshSeconds: z.ZodOptional<z.ZodNumber>;
};

export const paymasterAdminChainSectionSchema: z.ZodObject<
	PaymasterAdminChainSectionShape,
	z.core.$strict
> = z
	.object({
		walletRpcUrl: z.string().optional(),
		refreshSeconds: z.number().int().positive().optional(),
	})
	.strict();

type ForeignSection = z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodUnknown>>;

const foreignSection: ForeignSection = z
	.record(z.string(), z.unknown())
	.optional();

/**
 * One backend chain entry — the shape of the chain document wallet-api (`GIANO_CHAINS`),
 * giano-bundler (`GIANO_CHAINS`) and paymaster-admin (`GIANO_DEPLOYMENTS`) all read, from the
 * same secret, so they cannot disagree about a chain. What more than one of them reads sits at
 * the top — `rpcUrl`, `entryPoint` (wallet-api hashes against it, the bundler submits to it) and
 * `sponsorshipPaymaster` (wallet-api sponsors through it, the console administers it); each
 * service's own settings sit in its section, which that service validates strictly while accepting
 * the others' as-is. One exception: wallet-api also reads `bundler.chainType` (unless
 * `bundler.enabled` is false) for its gasless check, so a configured type is the answer for both.
 * `entryPoint` and `sponsorshipPaymaster` default from the contracts registry.
 * Submission keys never appear here: the document reaches wallet-api, which must not hold them.
 */
type BackendChainFields = {
	entryPoint: z.ZodOptional<z.ZodType<`0x${string}`>>;
	sponsorshipPaymaster: z.ZodOptional<z.ZodType<`0x${string}`>>;
};

const backendChainFields: BackendChainFields = {
	entryPoint: chainAddressSchema.optional(),
	sponsorshipPaymaster: chainAddressSchema.optional(),
};

/** wallet-api's reading of a backend chain entry. */
type WalletApiChainShape = z.core.util.Extend<
	ChainDescriptorShape,
	BackendChainFields & {
		walletApi: z.ZodDefault<
			z.ZodObject<WalletApiChainSectionShape, z.core.$strict>
		>;
		bundler: ForeignSection;
		paymasterAdmin: ForeignSection;
	}
>;

export const walletApiChainSchema: z.ZodObject<
	WalletApiChainShape,
	z.core.$strict
> = chainDescriptorSchema
	.extend({
		...backendChainFields,
		walletApi: walletApiChainSectionSchema.default({}),
		bundler: foreignSection,
		paymasterAdmin: foreignSection,
	})
	.strict();
export type WalletApiChain = z.infer<typeof walletApiChainSchema>;

/** giano-bundler's reading of a backend chain entry. */
type BundlerChainShape = z.core.util.Extend<
	ChainDescriptorShape,
	BackendChainFields & {
		walletApi: ForeignSection;
		// prefault, not default: zod 4 returns a default as-is, and the section's own defaults must apply.
		bundler: z.ZodPrefault<
			z.ZodObject<BundlerChainSectionShape, z.core.$strict>
		>;
		paymasterAdmin: ForeignSection;
	}
>;

export const bundlerChainSchema: z.ZodObject<
	BundlerChainShape,
	z.core.$strict
> = chainDescriptorSchema
	.extend({
		...backendChainFields,
		walletApi: foreignSection,
		bundler: bundlerChainSectionSchema.prefault({}),
		paymasterAdmin: foreignSection,
	})
	.strict();
export type BundlerChain = z.infer<typeof bundlerChainSchema>;

/**
 * @deprecated wallet-api reads {@link walletApiChainSchema} since the backend chain document
 * gained per-service sections. Kept so existing importers keep compiling.
 */
type BackendChainDescriptorShape = z.core.util.Extend<
	ChainDescriptorShape,
	{
		bundlerUrl: z.ZodString;
		entryPoint: z.ZodOptional<z.ZodType<`0x${string}`>>;
		factory: z.ZodOptional<z.ZodType<`0x${string}`>>;
		sponsorshipPaymaster: z.ZodOptional<z.ZodType<`0x${string}`>>;
		policy: z.ZodOptional<z.ZodObject<ChainPolicyShape, z.core.$strict>>;
	}
>;

export const backendChainDescriptorSchema: z.ZodObject<
	BackendChainDescriptorShape,
	z.core.$strip
> = chainDescriptorSchema.extend({
	bundlerUrl: z.string().url(),
	entryPoint: chainAddressSchema.optional(),
	factory: chainAddressSchema.optional(),
	sponsorshipPaymaster: chainAddressSchema.optional(),
	policy: chainPolicySchema.optional(),
});

export type BackendChainDescriptor = z.infer<
	typeof backendChainDescriptorSchema
>;

/** wallet-web's extension: what the browser needs; it never learns an endpoint it may not use. */
type WalletChainDescriptorShape = z.core.util.Extend<
	ChainDescriptorShape,
	{
		bundlerUrl: z.ZodString;
		factoryAddress: z.ZodOptional<z.ZodType<`0x${string}`>>;
		sponsorship: z.ZodOptional<
			z.ZodEnum<{
				service: "service";
				"test-paymaster": "test-paymaster";
				off: "off";
			}>
		>;
		paymasterServiceUrl: z.ZodOptional<z.ZodString>;
		testPaymasterAddress: z.ZodOptional<z.ZodType<`0x${string}`>>;
	}
>;

export const walletChainDescriptorSchema: z.ZodObject<
	WalletChainDescriptorShape,
	z.core.$strip
> = chainDescriptorSchema.extend({
	bundlerUrl: z.string().url(),
	factoryAddress: chainAddressSchema.optional(),
	sponsorship: z.enum(["service", "test-paymaster", "off"]).optional(),
	paymasterServiceUrl: z.string().optional(),
	testPaymasterAddress: chainAddressSchema.optional(),
});

export type WalletChainDescriptor = z.infer<typeof walletChainDescriptorSchema>;

/**
 * Validates a list of descriptors under the rules every consumer shares (MC-42):
 * at least one entry, unique chain ids, and no privileged entry (the shape has no way to
 * express one — that is the point). Returns readable errors naming the chain and field.
 */
export function validateChainList<T extends ChainDescriptor>(
	descriptors: T[],
): { errors: string[]; warnings: string[] } {
	const errors: string[] = [];
	const warnings: string[] = [];
	if (descriptors.length === 0)
		errors.push("at least one chain must be configured");
	const seenIds = new Set<number>();
	const seenNames = new Set<string>();
	for (const descriptor of descriptors) {
		if (seenIds.has(descriptor.chainId))
			errors.push(`duplicate chainId ${descriptor.chainId}`);
		seenIds.add(descriptor.chainId);
		// Operators read names; two chains called "Testnet" is an incident waiting to happen.
		if (seenNames.has(descriptor.name))
			warnings.push(`duplicate chain name "${descriptor.name}"`);
		seenNames.add(descriptor.name);
	}
	return { errors, warnings };
}

/**
 * The repository's local anvil chains: Devnet A (31337), Devnet B (31338) and Devnet SD (31339),
 * the node behind Silent Data's gateway. This is the one list of them. The deploy CLI treats them as
 * local (deploy/config.ts), and provision:paymaster signs with the Anvil key on them. Code that
 * cannot import this package keeps a copy that names this constant: the deployer image's entry
 * point (scripts/deployer-entrypoint.mjs, kept in step by a test), e2e/devnet/upgrade-paymaster.mjs
 * and services/paymaster-admin (LOCAL_DEVNET_CHAIN_IDS). Add a local chain here, in those copies,
 * and in KNOWN_CHAIN_NAMES below.
 */
export const LOCAL_CHAIN_IDS = [31337, 31338, 31339] as const;

/** Well-known chain names, used when a single-chain shorthand supplies no name. */
const KNOWN_CHAIN_NAMES: Record<number, string> = {
	1: "Ethereum",
	10: "OP Mainnet",
	8453: "Base",
	84532: "Base Sepolia",
	11155111: "Sepolia",
	31337: "Local devnet A",
	31338: "Local devnet B",
	31339: "Local devnet SD",
};

/** A display name for a chain: registry/known name, else "chain <id>" (never a bare number). */
export function defaultChainName(chainId: number): string {
	return KNOWN_CHAIN_NAMES[chainId] ?? `chain ${chainId}`;
}

/** True when the chain has a registry entry the descriptor's addresses may default from. */
export function hasRegistryEntry(chainId: number): boolean {
	return chainId in gianoAddresses;
}
