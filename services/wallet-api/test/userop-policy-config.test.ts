import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";
import {
	FALLBACK_FEE_CAPS,
	KNOWN_CHAIN_FEE_CAPS,
} from "../src/services/chain-fee-caps.js";

/**
 * Where the relay policy's per-chain defaults come from, and what a production deployment must
 * state before it boots (openspec change userop-policy-defaults). Pure config tests: no stack.
 */

const GWEI = 1_000_000_000n;
const ENTRY_POINT = "0x433709009B8330FDa32311DF1C2AFA402eD8D009";
const FACTORY = "0x2222222222222222222222222222222222222222";
const PAYMASTER = "0x1000000000000000000000000000000000000001";

const BASE_ENV = {
	NODE_ENV: "test",
	GIANO_DEPLOYMENT_CLASS: "development",
	GIANO_ENVIRONMENT: "test",
	LOG_LEVEL: "error",
	DATABASE_URL: "postgres://u:p@localhost:5432/x",
	METRICS_BEARER_TOKEN: "a-long-enough-metrics-token",
} as NodeJS.ProcessEnv;

const singleChain = (chainId: number, extra: Record<string, string> = {}) =>
	({
		...BASE_ENV,
		CHAIN_ID: String(chainId),
		RPC_URL: "http://a:8545",
		BUNDLER_URL: "http://a:4337",
		ENTRYPOINT_ADDRESS: ENTRY_POINT,
		FACTORY_ADDRESS: FACTORY,
		...extra,
	}) as NodeJS.ProcessEnv;

const multiChain = (
	chains: { chainId: number; policy?: Record<string, unknown> }[],
	extra: Record<string, string> = {},
) =>
	({
		...BASE_ENV,
		BUNDLER_BASE_URL: "http://bundler:4337",
		GIANO_CHAINS: JSON.stringify(
			chains.map(({ chainId, policy }) => ({
				chainId,
				name: `chain ${chainId}`,
				rpcUrl: "http://a:8545",
				entryPoint: ENTRY_POINT,
				walletApi: { factory: FACTORY, ...(policy ? { policy } : {}) },
			})),
		),
		...extra,
	}) as NodeJS.ProcessEnv;

const STATED = { allowedTargets: "any", allowedPaymasters: [PAYMASTER] };

describe("per-chain fee caps (G6 R2)", () => {
	it("gives a known L2 a cap that can fire, instead of the chain-agnostic 500 gwei", () => {
		const [base] = loadConfig(multiChain([{ chainId: 8453 }])).CHAINS;
		expect(base.policy.maxFeePerGas).toBe(10n * GWEI);
		expect(base.policy.maxPriorityFeePerGas).toBe(1n * GWEI);
		expect(base.policy.maxFeePerGas).toBeLessThan(
			FALLBACK_FEE_CAPS.maxFeePerGas,
		);
	});

	it("covers every public chain Giano serves today", () => {
		for (const chainId of [1, 10, 8453, 84532, 11155111]) {
			expect(KNOWN_CHAIN_FEE_CAPS[chainId], String(chainId)).toBeDefined();
		}
	});

	it("lets the descriptor's own cap win, then the env var when set", () => {
		const config = loadConfig(
			multiChain([{ chainId: 8453, policy: { maxFeePerGas: "123" } }], {
				USEROP_MAX_PRIORITY_FEE_PER_GAS: "45",
			}),
		);
		expect(config.CHAINS[0].policy).toMatchObject({
			maxFeePerGas: 123n,
			maxPriorityFeePerGas: 45n,
		});
	});

	it("leaves a chain with no known default to the fallback (local devnets)", () => {
		const [local] = loadConfig(singleChain(31337)).CHAINS;
		expect(local.policy.maxFeePerGas).toBeUndefined();
		// an empty env value is unset, not 0
		expect(
			loadConfig(singleChain(31337, { USEROP_MAX_FEE_PER_GAS: "" })).CHAINS[0]
				.policy.maxFeePerGas,
		).toBeUndefined();
	});

	it("reads the new gas caps from a descriptor and defaults them from the env", () => {
		const config = loadConfig(
			multiChain([
				{ chainId: 8453, policy: { maxPreVerificationGas: "2000000" } },
			]),
		);
		expect(config.CHAINS[0].policy.maxPreVerificationGas).toBe(2_000_000n);
		expect(config.USEROP_MAX_PRE_VERIFICATION_GAS).toBe(10_000_000n);
		expect(config.USEROP_MAX_PAYMASTER_VERIFICATION_GAS).toBe(1_000_000n);
		expect(config.USEROP_MAX_PAYMASTER_POST_OP_GAS).toBe(1_000_000n);
	});
});

describe('explicit allowlists: "any" or addresses (G6 R5)', () => {
	it('accepts "any" in a descriptor and in the single-chain env, as no restriction', () => {
		expect(
			loadConfig(
				multiChain([{ chainId: 8453, policy: { allowedTargets: "any" } }]),
			).CHAINS[0].policy.allowedTargets,
		).toEqual([]);
		expect(
			loadConfig(singleChain(31337, { USEROP_ALLOWED_TARGETS: "any" }))
				.CHAINS[0].policy.allowedTargets,
		).toEqual([]);
	});

	it("refuses a malformed single-chain allowlist", () => {
		expect(() =>
			loadConfig(singleChain(31337, { USEROP_ALLOWED_PAYMASTERS: "anything" })),
		).toThrow(/USEROP_ALLOWED_PAYMASTERS: must be "any"/);
	});

	it("refuses USEROP_ALLOWED_TARGETS=any with GIANO_CHAINS: allowlists are per chain (MC-61)", () => {
		expect(() =>
			loadConfig(
				multiChain([{ chainId: 8453 }], { USEROP_ALLOWED_TARGETS: "any" }),
			),
		).toThrow(/USEROP_ALLOWED_TARGETS is single-chain shorthand/);
	});
});

describe("production boot refusals (G6 R2, R5)", () => {
	const production = { GIANO_DEPLOYMENT_CLASS: "production" };

	it("boots when every chain states both allowlists and has a known fee cap", () => {
		expect(() =>
			loadConfig(multiChain([{ chainId: 8453, policy: STATED }], production)),
		).not.toThrow();
		expect(() =>
			loadConfig(
				singleChain(8453, {
					...production,
					USEROP_ALLOWED_TARGETS: "any",
					USEROP_ALLOWED_PAYMASTERS: PAYMASTER,
				}),
			),
		).not.toThrow();
	});

	it("refuses a chain whose allowlists are not stated, naming the chain and the field", () => {
		expect(() =>
			loadConfig(
				multiChain(
					[{ chainId: 8453, policy: { allowedTargets: "any" } }],
					production,
				),
			),
		).toThrow(/chain 8453: walletApi\.policy\.allowedPaymasters/);
		expect(() =>
			loadConfig(
				singleChain(8453, {
					...production,
					USEROP_ALLOWED_PAYMASTERS: PAYMASTER,
				}),
			),
		).toThrow(/chain 8453: USEROP_ALLOWED_TARGETS must be stated/);
	});

	it('refuses a separator-only allowlist: only "any" selects unrestricted', () => {
		for (const field of [
			"USEROP_ALLOWED_TARGETS",
			"USEROP_ALLOWED_PAYMASTERS",
		]) {
			expect(() =>
				loadConfig(
					singleChain(8453, {
						...production,
						USEROP_ALLOWED_TARGETS: "any",
						USEROP_ALLOWED_PAYMASTERS: PAYMASTER,
						[field]: " , ",
					}),
				),
			).toThrow(/must be "any" or comma-separated 0x addresses/);
		}
	});

	it("refuses a chain that would get the fallback fee cap", () => {
		expect(() =>
			loadConfig(multiChain([{ chainId: 777777, policy: STATED }], production)),
		).toThrow(/chain 777777: no maxFeePerGas cap is known/);
		// a descriptor cap, or the env, is enough
		expect(() =>
			loadConfig(
				multiChain(
					[
						{
							chainId: 777777,
							policy: {
								...STATED,
								maxFeePerGas: "1000000000",
								maxPriorityFeePerGas: "100000000",
							},
						},
					],
					production,
				),
			),
		).not.toThrow();
	});

	it("does not apply the production rules to a testnet or development deployment", () => {
		expect(() =>
			loadConfig(
				multiChain([{ chainId: 777777 }], {
					GIANO_DEPLOYMENT_CLASS: "testnet",
				}),
			),
		).not.toThrow();
	});
});
