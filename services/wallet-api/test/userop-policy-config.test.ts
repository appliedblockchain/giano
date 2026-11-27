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

describe("known fee caps (G6 R2)", () => {
	it("covers every public chain Giano serves today, below the chain-agnostic fallback", () => {
		for (const chainId of [1, 10, 8453, 84532, 11155111]) {
			expect(KNOWN_CHAIN_FEE_CAPS[chainId], String(chainId)).toBeDefined();
		}
		expect(KNOWN_CHAIN_FEE_CAPS[8453].maxFeePerGas).toBe(10n * GWEI);
		expect(KNOWN_CHAIN_FEE_CAPS[8453].maxFeePerGas).toBeLessThan(
			FALLBACK_FEE_CAPS.maxFeePerGas,
		);
	});
});

/**
 * Each chain's relay policy lives in the database (chain-policy.test.ts). What config resolves is
 * only what the deployment overrides, field by field, with where it was set (chain-relay-policy-console
 * design D2).
 */
describe("overrides (chain-relay-policy-console D2)", () => {
	it("lets the descriptor's own cap win, then the env var when set, each with its source", () => {
		const config = loadConfig(
			multiChain([{ chainId: 8453, policy: { maxFeePerGas: "123" } }], {
				USEROP_MAX_FEE_PER_GAS: "999",
				USEROP_MAX_PRIORITY_FEE_PER_GAS: "45",
			}),
		);
		expect(config.CHAINS[0].policy).toEqual({
			maxFeePerGas: { value: 123n, source: "GIANO_CHAINS" },
			maxPriorityFeePerGas: {
				value: 45n,
				source: "USEROP_MAX_PRIORITY_FEE_PER_GAS",
			},
		});
	});

	it("overrides nothing by default: an unset or empty env var leaves the stored value in charge", () => {
		const config = loadConfig(
			singleChain(31337, {
				USEROP_MAX_FEE_PER_GAS: "",
				USEROP_MAX_CALL_GAS: "",
			}),
		);
		expect(config.CHAINS[0].policy).toEqual({});
		expect(config.USEROP_MAX_CALL_GAS).toBeUndefined();
		expect(config.USEROP_MAX_PRE_VERIFICATION_GAS).toBeUndefined();
	});

	it("reads the gas caps from a descriptor and from the env", () => {
		const config = loadConfig(
			multiChain(
				[{ chainId: 8453, policy: { maxPreVerificationGas: "2000000" } }],
				{ USEROP_MAX_PAYMASTER_POST_OP_GAS: "300000" },
			),
		);
		expect(config.CHAINS[0].policy).toEqual({
			maxPreVerificationGas: { value: 2_000_000n, source: "GIANO_CHAINS" },
			maxPaymasterPostOpGas: {
				value: 300_000n,
				source: "USEROP_MAX_PAYMASTER_POST_OP_GAS",
			},
		});
	});

	it('reads "any", an address list and a legacy empty list from a descriptor and the single-chain env', () => {
		expect(
			loadConfig(
				multiChain([
					{
						chainId: 8453,
						policy: { allowedTargets: "any", allowedPaymasters: [PAYMASTER] },
					},
				]),
			).CHAINS[0].policy,
		).toEqual({
			allowedTargets: { value: "any", source: "GIANO_CHAINS" },
			allowedPaymasters: {
				value: [PAYMASTER.toLowerCase()],
				source: "GIANO_CHAINS",
			},
		});
		// an empty list has always meant "any address" in a descriptor
		expect(
			loadConfig(
				multiChain([{ chainId: 8453, policy: { allowedTargets: [] } }]),
			).CHAINS[0].policy.allowedTargets,
		).toEqual({ value: "any", source: "GIANO_CHAINS" });
		expect(
			loadConfig(singleChain(31337, { USEROP_ALLOWED_TARGETS: "any" }))
				.CHAINS[0].policy.allowedTargets,
		).toEqual({ value: "any", source: "USEROP_ALLOWED_TARGETS" });
	});

	it("refuses a malformed single-chain allowlist", () => {
		expect(() =>
			loadConfig(singleChain(31337, { USEROP_ALLOWED_PAYMASTERS: "anything" })),
		).toThrow(/USEROP_ALLOWED_PAYMASTERS: must be "any"/);
	});

	it('refuses a separator-only allowlist: only "any" selects unrestricted', () => {
		for (const field of [
			"USEROP_ALLOWED_TARGETS",
			"USEROP_ALLOWED_PAYMASTERS",
		]) {
			expect(() => loadConfig(singleChain(8453, { [field]: " , " }))).toThrow(
				/must be "any" or comma-separated 0x addresses/,
			);
		}
	});

	it("refuses USEROP_ALLOWED_TARGETS=any with GIANO_CHAINS: allowlists are per chain (MC-61)", () => {
		expect(() =>
			loadConfig(
				multiChain([{ chainId: 8453 }], { USEROP_ALLOWED_TARGETS: "any" }),
			),
		).toThrow(/USEROP_ALLOWED_TARGETS is single-chain shorthand/);
	});
});

describe("production boot (chain-relay-policy-console D4)", () => {
	it("boots with nothing stated: the stored policy decides, and a gap refuses that chain only", () => {
		expect(() =>
			loadConfig(
				multiChain([{ chainId: 8453 }, { chainId: 777777 }], {
					GIANO_DEPLOYMENT_CLASS: "production",
				}),
			),
		).not.toThrow();
	});
});
