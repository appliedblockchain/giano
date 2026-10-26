import { describe, expect, it } from "vitest";
import {
	ANVIL_KEY,
	ConfigError,
	DEFAULT_ENTRYPOINT,
	loadConfig,
} from "../src/config.js";

const KEY = `0x${"11".repeat(32)}`;
const chain = (extra: Record<string, unknown> = {}) => ({
	chainId: 31337,
	name: "Devnet A",
	rpcUrl: "http://anvil:8545",
	...extra,
});
const env = (
	chains: unknown[] = [chain()],
	extra: Record<string, string> = {},
) => ({
	GIANO_CHAINS: JSON.stringify(chains),
	BUNDLER_EXECUTOR_PRIVATE_KEYS: KEY,
	...extra,
});

describe("loadConfig", () => {
	it("requires the chain document and executor keys", () => {
		expect(() => loadConfig({ BUNDLER_EXECUTOR_PRIVATE_KEYS: KEY })).toThrow(
			/GIANO_CHAINS is required/,
		);
		expect(() =>
			loadConfig({ GIANO_CHAINS: JSON.stringify([chain()]) }),
		).toThrow(/BUNDLER_EXECUTOR_PRIVATE_KEYS is required/);
		expect(() =>
			loadConfig(env([chain()], { BUNDLER_EXECUTOR_PRIVATE_KEYS: "0x1234" })),
		).toThrow(ConfigError);
		expect(() =>
			loadConfig(
				env([chain()], { BUNDLER_EXECUTOR_PRIVATE_KEYS: `${KEY},${KEY}` }),
			),
		).toThrow(/same key twice/);
	});

	it("refuses the Anvil key outside dev mode", () => {
		expect(() =>
			loadConfig(env([chain()], { BUNDLER_EXECUTOR_PRIVATE_KEYS: ANVIL_KEY })),
		).toThrow(/well-known Anvil key/);
		expect(() =>
			loadConfig(
				env([chain()], {
					BUNDLER_EXECUTOR_PRIVATE_KEYS: `${KEY},${ANVIL_KEY}`,
					GIANO_DEV_MODE: "yes",
				}),
			),
		).toThrow(/well-known Anvil key/);
	});

	it("allows the Anvil key in dev mode, with a warning", () => {
		const config = loadConfig(
			env([chain()], {
				BUNDLER_EXECUTOR_PRIVATE_KEYS: ANVIL_KEY,
				GIANO_DEV_MODE: "true",
			}),
		);
		expect(config.warnings.join("\n")).toMatch(/GIANO_DEV_MODE=true/);
		expect(config.executors[0].address).toBe(
			"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		);
	});

	it("applies defaults, per chain and process-wide", () => {
		const config = loadConfig(env());
		expect(config).toMatchObject({
			port: 4337,
			resubmitTimeoutMs: 30_000,
			maxReplacements: 3,
			warnings: [],
		});
		expect(config.chains).toEqual([
			{
				chainId: 31337,
				name: "Devnet A",
				rpcUrl: "http://anvil:8545",
				entryPoint: DEFAULT_ENTRYPOINT,
				chainType: "auto",
				maxBlockRange: 2000n,
			},
		]);
	});

	it("serves every chain in the document, with one lane per key on each", () => {
		const second = `0x${"22".repeat(32)}`;
		const config = loadConfig(
			env(
				[
					chain(),
					chain({
						chainId: 84532,
						name: "Base Sepolia",
						rpcUrl: "https://base",
					}),
				],
				{ BUNDLER_EXECUTOR_PRIVATE_KEYS: `${KEY}, ${second}` },
			),
		);
		expect(config.chains.map((entry) => entry.chainId)).toEqual([31337, 84532]);
		expect(config.executors).toHaveLength(2);
	});

	it("reads its own section, and the shared entryPoint", () => {
		const entryPoint = "0x1111111111111111111111111111111111111111";
		const [resolved] = loadConfig(
			env([
				chain({
					entryPoint,
					bundler: {
						rpcUrl: "http://submission:8545",
						chainType: "op-stack",
						maxBlockRange: 500,
					},
				}),
			]),
		).chains;
		expect(resolved).toMatchObject({
			rpcUrl: "http://submission:8545",
			entryPoint,
			chainType: "op-stack",
			maxBlockRange: 500n,
		});
	});

	it("skips chains whose bundler section disables it, and refuses a document that leaves it nothing", () => {
		const config = loadConfig(
			env([
				chain(),
				chain({ chainId: 8453, name: "Base", bundler: { enabled: false } }),
			]),
		);
		expect(config.chains.map((entry) => entry.chainId)).toEqual([31337]);
		expect(() =>
			loadConfig(env([chain({ bundler: { enabled: false } })])),
		).toThrow(/enables no chain/);
	});

	it("accepts the other services' sections as-is, and validates its own strictly", () => {
		expect(() =>
			loadConfig(
				env([
					chain({
						sponsorshipPaymaster: "0xf98b56de62ce88cEb70A9155582248cDBf2D0718",
						walletApi: { factory: "0x2", anything: true },
						paymasterAdmin: { refreshSeconds: 5 },
					}),
				]),
			),
		).not.toThrow();
		expect(() =>
			loadConfig(env([chain({ bundler: { chaintype: "op-stack" } })])),
		).toThrow(/chaintype/);
		expect(() => loadConfig(env([chain({ bundlerUrl: "http://x" })]))).toThrow(
			/bundlerUrl/,
		);
	});

	it("refuses a malformed or duplicated document", () => {
		expect(() => loadConfig({ ...env(), GIANO_CHAINS: "{" })).toThrow(
			/not valid JSON/,
		);
		expect(() => loadConfig(env([chain(), chain()]))).toThrow(
			/duplicate chainId 31337/,
		);
		expect(() => loadConfig(env([]))).toThrow(/at least one chain/);
	});

	it("refuses the single-chain variables GIANO_CHAINS replaced", () => {
		expect(() =>
			loadConfig({ ...env(), BUNDLER_RPC_URL: "http://anvil:8545" }),
		).toThrow(/no longer read: BUNDLER_RPC_URL/);
		expect(() =>
			loadConfig({
				...env(),
				ALTO_EXECUTOR_PRIVATE_KEYS: KEY,
				ALTO_SAFE_MODE: "true",
			}),
		).toThrow(/no longer read: ALTO_EXECUTOR_PRIVATE_KEYS, ALTO_SAFE_MODE/);
	});

	it("treats empty values as unset", () => {
		expect(
			loadConfig({ ...env(), BUNDLER_PORT: "", BUNDLER_RPC_URL: "" }).port,
		).toBe(4337);
	});
});
