import {
	ENTRYPOINT_V09_ADDRESS,
	entryPointRuntimeCode,
	gianoAddresses,
	type ReleaseContractName,
} from "@appliedblockchain/giano-contracts";
import Fastify from "fastify";
import { keccak256, type PublicClient } from "viem";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import connectorPackage from "../../../packages/connector/package.json" with {
	type: "json",
};
import { loadConfig } from "../src/config.js";
import chainPlugin from "../src/plugins/chain.js";
import {
	isFatalFailure,
	probeDivergence,
	recoveryDivergence,
	verifyChain,
} from "../src/services/chain-verify.js";
import type { ChainRegistry, ChainServices } from "../src/services/chains.js";
import {
	startTestStack,
	stopTestStack,
	TENANT_A,
	type TestContext,
} from "./setup.js";
import {
	createAuthenticator,
	makeRegistrationResponse,
} from "./webauthn-fixtures.js";

/** Any address will do: nothing compares a contract's address with a constant. */
const FACTORY = "0x9c01925D07527A7920031196396A9c37421715A2" as const;
const IMPLEMENTATION = "0x44EF48A4BEaD5571B3B13b81400EA7930e5810D6" as const;
const PAYMASTER_IMPLEMENTATION = "0x326549c3600BFA31CB44213Df0576AE79E70E4aC";

const BASE_ENV = {
	NODE_ENV: "test",
	GIANO_DEPLOYMENT_CLASS: "development",
	GIANO_ENVIRONMENT: "test",
	LOG_LEVEL: "error",
	DATABASE_URL: "postgres://u:p@localhost:5432/x",
} as NodeJS.ProcessEnv;

describe("config: the chain list", () => {
	it("normalises the single-chain scalar shorthand into a one-entry list (MC-47, MC-132)", () => {
		const config = loadConfig({
			...BASE_ENV,
			CHAIN_ID: "31337",
			RPC_URL: "http://a:8545",
			BUNDLER_URL: "http://a:4337",
			ENTRYPOINT_ADDRESS: "0x433709009B8330FDa32311DF1C2AFA402eD8D009",
			FACTORY_ADDRESS: "0x2222222222222222222222222222222222222222",
			USEROP_ALLOWED_PAYMASTERS: "0x1000000000000000000000000000000000000001",
		});
		expect(config.CHAINS).toHaveLength(1);
		expect(config.CHAINS[0]).toMatchObject({
			chainId: 31337,
			rpcUrl: "http://a:8545",
			bundlerUrl: "http://a:4337",
			factory: "0x2222222222222222222222222222222222222222",
		});
		// address-valued env defaults fold into the sole chain's policy (MC-61)
		expect(config.CHAINS[0].policy.allowedPaymasters).toEqual([
			"0x1000000000000000000000000000000000000001",
		]);
		expect(config.CHAINS[0].name).not.toMatch(/^\d+$/); // never a bare number (MC-81)
	});

	it("IMPLEMENTATION_ADDRESS gives a single-chain shorthand outside the registry its implementation", () => {
		const config = loadConfig({
			...BASE_ENV,
			CHAIN_ID: "31337",
			RPC_URL: "http://a:8545",
			BUNDLER_URL: "http://a:4337",
			ENTRYPOINT_ADDRESS: "0x433709009B8330FDa32311DF1C2AFA402eD8D009",
			FACTORY_ADDRESS: "0x2222222222222222222222222222222222222222",
			IMPLEMENTATION_ADDRESS: "0x3333333333333333333333333333333333333333",
		});
		expect(config.CHAINS[0].implementation).toBe(
			"0x3333333333333333333333333333333333333333",
		);
	});

	it("accepts GIANO_CHAINS, resolving registry defaults per chain (MC-46)", () => {
		// The registry holds a chain once its deployment record is committed; stand one in for Base
		// the way gen:addresses would write it.
		gianoAddresses[8453] = {
			entryPoint: ENTRYPOINT_V09_ADDRESS,
			factory: FACTORY,
			implementation: IMPLEMENTATION,
		};
		try {
			const config = loadConfig({
				...BASE_ENV,
				GIANO_CHAINS: JSON.stringify([
					{
						chainId: 8453,
						name: "Base",
						rpcUrl: "http://a:8545",
						walletApi: { bundlerUrl: "http://a:4337" },
					},
					{
						chainId: 31338,
						name: "Devnet B",
						rpcUrl: "http://b:8545",
						entryPoint: "0x433709009B8330FDa32311DF1C2AFA402eD8D009",
						walletApi: {
							bundlerUrl: "http://b:4337",
							factory: FACTORY,
						},
					},
				]),
			});
			expect(config.CHAINS.map((chain) => chain.chainId)).toEqual([
				8453, 31338,
			]);
			// Base's addresses default from the contracts registry
			expect(config.CHAINS[0].factory).toBe(FACTORY);
			expect(config.CHAINS[0].implementation).toBe(IMPLEMENTATION);
			// a chain the registry does not list has no implementation unless walletApi names one
			expect(config.CHAINS[1].implementation).toBeUndefined();
		} finally {
			delete gianoAddresses[8453];
		}
	});

	it("walletApi.implementation overrides the registry's wallet implementation (per-chain addresses)", () => {
		gianoAddresses[8453] = {
			entryPoint: ENTRYPOINT_V09_ADDRESS,
			factory: FACTORY,
			implementation: IMPLEMENTATION,
		};
		try {
			const config = loadConfig({
				...BASE_ENV,
				GIANO_CHAINS: JSON.stringify([
					{
						chainId: 8453,
						name: "Base",
						rpcUrl: "http://a:8545",
						walletApi: {
							bundlerUrl: "http://a:4337",
							factory: "0x3333333333333333333333333333333333333333",
							implementation: "0x4444444444444444444444444444444444444444",
						},
					},
				]),
			});
			expect(config.CHAINS[0].factory).toBe(
				"0x3333333333333333333333333333333333333333",
			);
			expect(config.CHAINS[0].implementation).toBe(
				"0x4444444444444444444444444444444444444444",
			);
			expect(() =>
				loadConfig({
					...BASE_ENV,
					GIANO_CHAINS: JSON.stringify([
						{
							chainId: 8453,
							name: "Base",
							rpcUrl: "http://a:8545",
							walletApi: {
								bundlerUrl: "http://a:4337",
								implementation: "not an address",
							},
						},
					]),
				}),
			).toThrow();
		} finally {
			delete gianoAddresses[8453];
		}
	});

	it("refuses a chain that is neither in the registry nor given its addresses", () => {
		expect(() =>
			loadConfig({
				...BASE_ENV,
				GIANO_CHAINS: JSON.stringify([
					{
						chainId: 424242,
						name: "Unregistered",
						rpcUrl: "http://a:8545",
						walletApi: { bundlerUrl: "http://a:4337" },
					},
				]),
			}),
		).toThrow(
			/chain 424242: entryPoint required — the chain is not in the giano-contracts address registry/,
		);
	});

	describe("the document giano-bundler shares", () => {
		const chain = (extra: Record<string, unknown> = {}) => ({
			chainId: 31337,
			name: "A",
			rpcUrl: "http://a:8545",
			entryPoint: "0x433709009B8330FDa32311DF1C2AFA402eD8D009",
			walletApi: { factory: FACTORY },
			...extra,
		});

		it("submits to <BUNDLER_BASE_URL>/<chainId> unless walletApi.bundlerUrl says otherwise", () => {
			const config = loadConfig({
				...BASE_ENV,
				BUNDLER_BASE_URL: "http://bundler:4337/",
				GIANO_CHAINS: JSON.stringify([
					chain(),
					chain({
						chainId: 31338,
						name: "B",
						walletApi: {
							factory: FACTORY,
							bundlerUrl: "https://external.example/rpc",
						},
					}),
				]),
			});
			expect(config.CHAINS.map((resolved) => resolved.bundlerUrl)).toEqual([
				"http://bundler:4337/31337",
				"https://external.example/rpc",
			]);
		});

		it("reads the shared sponsorshipPaymaster, the one paymaster-admin administers", () => {
			const paymaster = "0xf98b56de62ce88cEb70A9155582248cDBf2D0718";
			const config = loadConfig({
				...BASE_ENV,
				BUNDLER_BASE_URL: "http://bundler:4337",
				GIANO_CHAINS: JSON.stringify([
					chain({ sponsorshipPaymaster: paymaster }),
				]),
			});
			expect(config.CHAINS[0].sponsorshipPaymaster).toBe(paymaster);
		});

		it("needs a bundler for every chain", () => {
			expect(() =>
				loadConfig({ ...BASE_ENV, GIANO_CHAINS: JSON.stringify([chain()]) }),
			).toThrow(/BUNDLER_BASE_URL.*31337 names no walletApi.bundlerUrl/s);
			expect(() =>
				loadConfig({
					...BASE_ENV,
					BUNDLER_BASE_URL: "http://bundler:4337",
					GIANO_CHAINS: JSON.stringify([
						chain({ bundler: { enabled: false } }),
					]),
				}),
			).toThrow(/bundler.enabled is false, so walletApi.bundlerUrl must name/);
		});

		it("accepts the bundler's section as-is, and validates its own strictly", () => {
			const env = { ...BASE_ENV, BUNDLER_BASE_URL: "http://bundler:4337" };
			expect(() =>
				loadConfig({
					...env,
					GIANO_CHAINS: JSON.stringify([
						chain({
							bundler: { chainType: "op-stack", anything: 1 },
							paymasterAdmin: { refreshSeconds: 5 },
						}),
					]),
				}),
			).not.toThrow();
			expect(() =>
				loadConfig({
					...env,
					GIANO_CHAINS: JSON.stringify([
						chain({ walletApi: { factory: FACTORY, factroy: "0x" } }),
					]),
				}),
			).toThrow(/factroy/);
		});

		it("refuses the pre-sections flat shape rather than guessing at it", () => {
			expect(() =>
				loadConfig({
					...BASE_ENV,
					GIANO_CHAINS: JSON.stringify([
						{
							...chain(),
							walletApi: undefined,
							bundlerUrl: "http://a:4337",
							factory: FACTORY,
						},
					]),
				}),
			).toThrow(/bundlerUrl|factory/);
		});

		it("keeps BUNDLER_BASE_URL to GIANO_CHAINS", () => {
			expect(() =>
				loadConfig({
					...BASE_ENV,
					CHAIN_ID: "31337",
					RPC_URL: "http://a:8545",
					BUNDLER_URL: "http://a:4337",
					BUNDLER_BASE_URL: "http://b:4337",
				}),
			).toThrow(/BUNDLER_BASE_URL goes with GIANO_CHAINS/);
		});
	});

	it("refuses BOTH the shorthand and GIANO_CHAINS — never a merge (§3.4)", () => {
		expect(() =>
			loadConfig({
				...BASE_ENV,
				CHAIN_ID: "31337",
				RPC_URL: "http://a:8545",
				BUNDLER_URL: "http://a:4337",
				GIANO_CHAINS: "[]",
			}),
		).toThrow(/mutually exclusive/);
	});

	it("refuses a configuration that names no chain at all", () => {
		expect(() => loadConfig({ ...BASE_ENV })).toThrow(
			/GIANO_CHAINS.*or CHAIN_ID/s,
		);
	});

	it("refuses duplicate chain ids", () => {
		const entry = {
			chainId: 31337,
			name: "A",
			rpcUrl: "http://a:8545",
			entryPoint: "0x433709009B8330FDa32311DF1C2AFA402eD8D009",
			walletApi: { bundlerUrl: "http://a:4337", factory: FACTORY },
		};
		expect(() =>
			loadConfig({ ...BASE_ENV, GIANO_CHAINS: JSON.stringify([entry, entry]) }),
		).toThrow(/duplicate chainId/);
	});

	it("refuses chain-agnostic address-valued env vars alongside GIANO_CHAINS (MC-61)", () => {
		expect(() =>
			loadConfig({
				...BASE_ENV,
				GIANO_CHAINS: JSON.stringify([
					{
						chainId: 31337,
						name: "A",
						rpcUrl: "http://a:8545",
						entryPoint: "0x433709009B8330FDa32311DF1C2AFA402eD8D009",
						walletApi: {
							bundlerUrl: "http://a:4337",
							factory: FACTORY,
						},
					},
				]),
				USEROP_ALLOWED_TARGETS: "0x1000000000000000000000000000000000000001",
			}),
		).toThrow(/USEROP_ALLOWED_TARGETS is single-chain shorthand/);
	});
});

// ── requireChain: per-request resolution (MC-51–MC-55, §9.3) ─────────────────────

function fakeChain(
	chainId: number,
	status: "ready" | "unavailable" = "ready",
): ChainServices {
	return {
		chainId,
		status,
		descriptor: { chainId },
	} as unknown as ChainServices;
}

function fakeRegistry(chains: ChainServices[]): ChainRegistry {
	const byId = new Map(chains.map((chain) => [chain.chainId, chain]));
	return {
		get: (chainId) => {
			const chain = byId.get(chainId);
			if (!chain) throw new Error("unknown");
			return chain;
		},
		tryGet: (chainId) => byId.get(chainId),
		get sole() {
			if (chains.length !== 1) throw new Error("sole with several chains");
			return chains[0];
		},
		get all() {
			return chains;
		},
		get size() {
			return chains.length;
		},
		servedChainIds: () => chains.map((chain) => chain.chainId),
		anyReady: () => chains.find((chain) => chain.status === "ready")!,
	};
}

async function appWithChains(chains: ChainServices[]) {
	const app = Fastify({ logger: false });
	await app.register(chainPlugin, { registry: fakeRegistry(chains) });
	app.post("/probe", { preHandler: app.requireChain }, async (request) => ({
		resolved: request.chain!.chainId,
	}));
	return app;
}

describe("requireChain", () => {
	it("resolves a named, served chain", async () => {
		const app = await appWithChains([fakeChain(31337), fakeChain(31338)]);
		const response = await app.inject({
			method: "POST",
			url: "/probe",
			payload: { chainId: 31338 },
		});
		expect(response.json()).toEqual({ resolved: 31338 });
	});

	it("applies an omitted chain to the sole configured chain (MC-53)", async () => {
		const app = await appWithChains([fakeChain(31337)]);
		const response = await app.inject({
			method: "POST",
			url: "/probe",
			payload: {},
		});
		expect(response.json()).toEqual({ resolved: 31337 });
	});

	it("refuses omission as ambiguous when several chains are served — never guesses (MC-53)", async () => {
		const app = await appWithChains([fakeChain(31337), fakeChain(31338)]);
		const response = await app.inject({
			method: "POST",
			url: "/probe",
			payload: {},
		});
		expect(response.statusCode).toBe(400);
		expect(response.json()).toMatchObject({
			error: "chain-required",
			servedChainIds: [31337, 31338],
		});
	});

	it("refuses an unserved chain with a distinct, machine-readable reason (MC-52)", async () => {
		const app = await appWithChains([fakeChain(31337)]);
		const response = await app.inject({
			method: "POST",
			url: "/probe",
			payload: { chainId: 10 },
		});
		expect(response.statusCode).toBe(400);
		expect(response.json()).toMatchObject({
			error: "unsupported-chain",
			servedChainIds: [31337],
		});
	});

	it('distinguishes "not served" (permanent) from "temporarily unavailable" (retryable) (MC-55)', async () => {
		const app = await appWithChains([
			fakeChain(31337),
			fakeChain(31338, "unavailable"),
		]);
		const response = await app.inject({
			method: "POST",
			url: "/probe",
			payload: { chainId: 31338 },
		});
		expect(response.statusCode).toBe(503);
		expect(response.json()).toMatchObject({ error: "chain-unavailable" });
	});

	it("reads the ERC-7677 chain from params[2]", async () => {
		const app = await appWithChains([fakeChain(31337), fakeChain(31338)]);
		const response = await app.inject({
			method: "POST",
			url: "/probe",
			payload: { params: [{}, "0x", "0x7a6a"] },
		});
		expect(response.json()).toEqual({ resolved: 31338 });
	});
});

// ── verifyChain: the boot-time gate (§3.5, §4.2) ─────────────────────────────────

type FakeClientBehaviour = {
	chainId?: number | Error;
	code?: Record<string, string>;
	implementation?: string;
	/** What the implementation's entryPoint() returns. */
	boundEntryPoint?: string;
	probeAddress?: string;
	/** What the paymaster proxy's ERC-1967 implementation slot holds. */
	paymasterImplementation?: string;
};

function fakeClient(behaviour: FakeClientBehaviour): PublicClient {
	return {
		async getChainId() {
			if (behaviour.chainId instanceof Error) throw behaviour.chainId;
			return behaviour.chainId ?? 31337;
		},
		async getCode({ address }: { address: string }) {
			const code = behaviour.code?.[address.toLowerCase()];
			if (code !== undefined) return code;
			// The EntryPoint runs its real runtime; every other address the stand-in release code.
			return address.toLowerCase() === ENTRYPOINT_V09_ADDRESS.toLowerCase()
				? entryPointRuntimeCode(
						typeof behaviour.chainId === "number" ? behaviour.chainId : 31337,
					)
				: "0xabcd";
		},
		async getStorageAt() {
			return `0x${(behaviour.paymasterImplementation ?? PAYMASTER_IMPLEMENTATION).slice(2).padStart(64, "0")}`;
		},
		async readContract({ functionName }: { functionName: string }) {
			if (functionName === "implementation")
				return behaviour.implementation ?? IMPLEMENTATION;
			if (functionName === "entryPoint")
				return behaviour.boundEntryPoint ?? ENTRYPOINT_V09_ADDRESS;
			if (functionName === "getAddress")
				return (
					behaviour.probeAddress ?? "0x00000000000000000000000000000000000abcde"
				);
			throw new Error(`unexpected read: ${functionName}`);
		},
	} as unknown as PublicClient;
}

const descriptor = {
	chainId: 31337,
	name: "A",
	rpcUrl: "http://a",
	bundlerUrl: "http://a-b",
	entryPoint: "0x433709009B8330FDa32311DF1C2AFA402eD8D009" as const,
	factory: FACTORY,
	implementation: IMPLEMENTATION,
	policy: { allowedTargets: [], allowedPaymasters: [] },
};

/** The fake client's default code (`0xabcd`) stands in for every release contract's code. */
const fakeRelease = (_contract: ReleaseContractName, code: string) =>
	code === "0xabcd" ? { release: "v2" } : undefined;

describe("verifyChain", () => {
	it("passes a healthy chain", async () => {
		const result = await verifyChain(descriptor, fakeClient({}), fakeRelease);
		expect(result.failures).toEqual([]);
		expect(result.factoryRelease).toBe("v2");
		expect(result.implementationAddress).toBe(IMPLEMENTATION);
		expect(result.probeAddress).toBeTruthy();
	});

	it("an endpoint reporting a different chain id is FATAL (MC-49)", async () => {
		const result = await verifyChain(
			descriptor,
			fakeClient({ chainId: 31338 }),
			fakeRelease,
		);
		expect(result.failures).toEqual([
			{ kind: "chain-id-mismatch", declared: 31337, reported: 31338 },
		]);
		expect(result.failures.every(isFatalFailure)).toBe(true);
	});

	it("an unreachable endpoint is NOT fatal — the deployment starts and retries (MC-54, MC-92)", async () => {
		const result = await verifyChain(
			descriptor,
			fakeClient({ chainId: new Error("connect ECONNREFUSED") }),
			fakeRelease,
		);
		expect(result.reachable).toBe(false);
		expect(result.failures).toHaveLength(1);
		expect(isFatalFailure(result.failures[0])).toBe(false);
	});

	it("admits release code at any factory address — no address is compared with a constant", async () => {
		const elsewhere = {
			...descriptor,
			factory: "0x3451C87749FE28Af2995f644aBc8d5B1c61A6191" as `0x${string}`,
		};
		const result = await verifyChain(elsewhere, fakeClient({}), fakeRelease);
		expect(result.failures).toEqual([]);
	});

	it("a factory cloning another implementation than the chain's is FATAL, showing both", async () => {
		const result = await verifyChain(
			descriptor,
			fakeClient({
				implementation: "0x9999999999999999999999999999999999999999",
			}),
			fakeRelease,
		);
		expect(result.failures).toEqual([
			{
				kind: "implementation-mismatch",
				expected: IMPLEMENTATION,
				found: "0x9999999999999999999999999999999999999999",
			},
		]);
		expect(result.failures.every(isFatalFailure)).toBe(true);
	});

	it("without a registered implementation, the factory's own is still checked for release code", async () => {
		const { implementation: _none, ...unregistered } = descriptor;
		const result = await verifyChain(
			unregistered,
			fakeClient({ code: { [IMPLEMENTATION.toLowerCase()]: "0xdead" } }),
			fakeRelease,
		);
		expect(result.failures).toEqual([
			{
				kind: "code-not-release",
				contract: "implementation",
				address: IMPLEMENTATION,
				codehash: keccak256("0xdead"),
			},
		]);
		expect(result.implementationUnchecked).toBe(true);
	});

	it("checks release code at the address it was read from (a UUPS __self must be that address)", async () => {
		const seen: string[] = [];
		await verifyChain(descriptor, fakeClient({}), (contract, code, address) => {
			seen.push(`${contract}@${address.toLowerCase()}`);
			return fakeRelease(contract, code);
		});
		expect(seen).toContain(`GianoSmartWallet@${IMPLEMENTATION.toLowerCase()}`);
	});

	it("a factory running code no release has is FATAL (an address does not prove code)", async () => {
		const result = await verifyChain(
			descriptor,
			fakeClient({ code: { [FACTORY.toLowerCase()]: "0xdead" } }),
			fakeRelease,
		);
		expect(result.failures).toContainEqual({
			kind: "code-not-release",
			contract: "factory",
			address: FACTORY,
			codehash: keccak256("0xdead"),
		});
		expect(result.failures.every(isFatalFailure)).toBe(true);
	});

	it("a paymaster proxy pointing at code no paymaster release has is FATAL", async () => {
		const result = await verifyChain(
			{
				...descriptor,
				sponsorshipPaymaster: "0x4Bf0c2F63C4fA20D88B8126298fFFC64710Ece96",
			},
			fakeClient({
				code: { [PAYMASTER_IMPLEMENTATION.toLowerCase()]: "0xdead" },
			}),
			fakeRelease,
		);
		expect(result.failures).toEqual([
			{
				kind: "code-not-release",
				contract: "paymaster-implementation",
				address: PAYMASTER_IMPLEMENTATION,
				codehash: keccak256("0xdead"),
			},
		]);
	});

	it("two chains with different paymaster addresses are both admitted", async () => {
		const probes = new Map<number, string>();
		for (const [chainId, paymaster] of [
			[8453, "0x1111111111111111111111111111111111111111"],
			[10, "0x2222222222222222222222222222222222222222"],
		] as const) {
			const result = await verifyChain(
				{ ...descriptor, chainId, sponsorshipPaymaster: paymaster },
				fakeClient({ chainId }),
				fakeRelease,
			);
			expect(result.failures).toEqual([]);
			expect(result.paymasterPresent).toBe(true);
			probes.set(chainId, result.probeAddress as string);
		}
		expect(probeDivergence(probes)).toBeNull();
	});

	it("served chains whose factories derive different probe addresses refuse start-up, naming both (MC-22)", async () => {
		const probes = new Map<number, string>();
		for (const [chainId, probeAddress] of [
			[8453, "0x00000000000000000000000000000000000abcde"],
			[10, "0x00000000000000000000000000000000000fffff"],
		] as const) {
			const result = await verifyChain(
				{ ...descriptor, chainId },
				fakeClient({ chainId, probeAddress }),
				fakeRelease,
			);
			probes.set(chainId, result.probeAddress as string);
		}
		const refusal = probeDivergence(probes);
		expect(refusal).toMatch(/address-identity violation/);
		expect(refusal).toContain(
			"chain 8453 → 0x00000000000000000000000000000000000abcde",
		);
		expect(refusal).toContain(
			"chain 10 → 0x00000000000000000000000000000000000fffff",
		);
	});

	it("a chain recovering after boot must derive the served chains' probe address (MC-22)", () => {
		const served = new Map([
			[8453, "0x00000000000000000000000000000000000abcde"],
		]);
		expect(
			recoveryDivergence(
				served,
				10,
				"0x00000000000000000000000000000000000ABCDE",
			),
		).toBeNull();
		const refusal = recoveryDivergence(
			served,
			10,
			"0x00000000000000000000000000000000000fffff",
		);
		expect(refusal).toContain(
			"chain 8453 → 0x00000000000000000000000000000000000abcde",
		);
		expect(refusal).toContain(
			"chain 10 → 0x00000000000000000000000000000000000fffff",
		);
		// The first chain admitted sets the reference for the rest.
		expect(
			recoveryDivergence(
				new Map(),
				10,
				"0x00000000000000000000000000000000000fffff",
			),
		).toBeNull();
	});

	it("a missing EntryPoint is FATAL (MC-141)", async () => {
		const result = await verifyChain(
			descriptor,
			fakeClient({ code: { [descriptor.entryPoint.toLowerCase()]: "0x" } }),
			fakeRelease,
		);
		expect(
			result.failures.some((failure) => failure.kind === "entrypoint-missing"),
		).toBe(true);
	});

	it("an EntryPoint other than v0.9 is FATAL — every hash Giano computes is a v0.9 hash", async () => {
		const v07 = "0x0000000071727De22E5E9d8BAf0edAc6f37da032" as const;
		const result = await verifyChain(
			{ ...descriptor, entryPoint: v07 },
			fakeClient({ code: { [v07.toLowerCase()]: "0x6001" } }),
			fakeRelease,
		);
		expect(result.failures).toContainEqual({
			kind: "entrypoint-not-canonical",
			address: v07,
			reason: "address",
		});
		expect(result.failures.every(isFatalFailure)).toBe(true);
	});

	it("non-canonical code at the v0.9 EntryPoint address is FATAL", async () => {
		const result = await verifyChain(
			descriptor,
			fakeClient({
				code: { [descriptor.entryPoint.toLowerCase()]: "0x6001" },
			}),
			fakeRelease,
		);
		expect(result.failures).toEqual([
			{
				kind: "entrypoint-not-canonical",
				address: descriptor.entryPoint,
				reason: "code",
			},
		]);
	});

	it("an earlier release's implementation, bound to another EntryPoint, is FATAL", async () => {
		const v07 = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";
		const result = await verifyChain(
			descriptor,
			fakeClient({ boundEntryPoint: v07 }),
			fakeRelease,
		);
		expect(result.failures).toEqual([
			{
				kind: "implementation-entrypoint-mismatch",
				implementation: IMPLEMENTATION,
				expected: descriptor.entryPoint,
				found: v07,
			},
		]);
	});
});

// ── The relay against a TWO-chain registry (testcontainers) ─────────────────────

describe("two-chain relay", () => {
	let ctx: TestContext;
	let sessionToken: string;
	let walletAddress: string;

	const CHAIN_A_BUNDLER = "http://bundler-a.test";
	const CHAIN_B_BUNDLER = "http://bundler-b.test";

	beforeAll(async () => {
		ctx = await startTestStack({
			GIANO_CHAINS: JSON.stringify([
				{
					chainId: 31337,
					name: "Devnet A",
					// both point at the same mock RPC; the mock answers eth_chainId 0x7a69 (31337),
					// which only chain A declares — chain B is left structurally unverified here
					// because buildApp does not verify (index.ts does), and the relay path is what
					// this suite exercises
					rpcUrl: "http://rpc-a.invalid",
					entryPoint: "0x433709009B8330FDa32311DF1C2AFA402eD8D009",
					walletApi: {
						bundlerUrl: CHAIN_A_BUNDLER,
						factory: "0x2222222222222222222222222222222222222222",
					},
				},
				{
					chainId: 31338,
					name: "Devnet B",
					rpcUrl: "http://rpc-b.invalid",
					entryPoint: "0x433709009B8330FDa32311DF1C2AFA402eD8D009",
					walletApi: {
						bundlerUrl: CHAIN_B_BUNDLER,
						factory: "0x2222222222222222222222222222222222222222",
					},
				},
			]),
		});
		// point chain A's read path at the live mock RPC so registration derives an address
		// (the registry holds per-chain clients built from the descriptor URLs, so instead we
		// register through the sole ready path: patch the descriptor before first use)
		const chainA = ctx.app.chains.get(31337);
		(chainA as { publicClient: unknown }).publicClient = (
			await import("viem")
		).createPublicClient({
			transport: (await import("viem")).http(ctx.rpc.url),
		});

		const auth = createAuthenticator();
		const options = await ctx.app.inject({
			method: "POST",
			url: "/v1/webauthn/options",
			headers: { origin: TENANT_A.walletOrigin },
			payload: { externalUserId: "multichain-user", kind: "registration" },
		});
		expect(options.statusCode).toBe(200);
		const { challenge } = options.json() as { challenge: string };
		const verify = await ctx.app.inject({
			method: "POST",
			url: "/v1/webauthn/registration/verify",
			headers: { origin: TENANT_A.walletOrigin },
			payload: {
				externalUserId: "multichain-user",
				response: makeRegistrationResponse(auth, {
					challenge,
					origin: TENANT_A.walletOrigin,
					rpId: TENANT_A.rpId,
				}),
			},
		});
		expect(verify.statusCode).toBe(200);
		const body = verify.json() as {
			walletAddress: string;
			session: { token: string };
		};
		sessionToken = body.session.token;
		walletAddress = body.walletAddress;
	}, 120_000);

	afterAll(async () => {
		if (ctx) await stopTestStack(ctx);
	});

	const makeOp = (nonce: number) => ({
		sender: walletAddress,
		nonce: `0x${nonce.toString(16)}`,
		callData: "0x",
		callGasLimit: "0x30000",
		verificationGasLimit: "0x30000",
		preVerificationGas: "0x10000",
		maxFeePerGas: "0x3b9aca00",
		maxPriorityFeePerGas: "0x3b9aca00",
		signature: "0x1234",
	});

	it("routes each operation to ITS chain's bundler, and changing the chain changes the endpoint (MC-113, MC-58)", async () => {
		const onA = await ctx.app.inject({
			method: "POST",
			url: "/v1/userops",
			headers: { authorization: `Bearer ${sessionToken}` },
			payload: { chainId: 31337, userOperation: makeOp(1) },
		});
		expect(onA.statusCode).toBe(200);
		const onB = await ctx.app.inject({
			method: "POST",
			url: "/v1/userops",
			headers: { authorization: `Bearer ${sessionToken}` },
			payload: { chainId: 31338, userOperation: makeOp(1) },
		});
		expect(onB.statusCode).toBe(200);

		const sends = ctx.bundlerCalls.filter(
			(call) => call.method === "eth_sendUserOperation",
		);
		expect(sends.map((call) => call.url)).toEqual([
			CHAIN_A_BUNDLER,
			CHAIN_B_BUNDLER,
		]);

		// The SAME operation on two chains has two different hashes: the hash commits to the
		// resolved chain (MC-57), so a submission cannot be replayed across chains.
		const hashA = (onA.json() as { userOperationHash: string })
			.userOperationHash;
		const hashB = (onB.json() as { userOperationHash: string })
			.userOperationHash;
		expect(hashA).not.toBe(hashB);

		// The audit trail answers "which chain did this go to" directly (MC-59).
		const rowB = await ctx.app.inject({
			method: "GET",
			url: `/v1/userops/${hashB}`,
			headers: { authorization: `Bearer ${sessionToken}` },
		});
		expect((rowB.json() as { chainId: number }).chainId).toBe(31338);
	});

	it("refuses an omitted chainId as ambiguous when several chains are served (MC-53)", async () => {
		const res = await ctx.app.inject({
			method: "POST",
			url: "/v1/userops",
			headers: { authorization: `Bearer ${sessionToken}` },
			payload: { userOperation: makeOp(2) },
		});
		expect(res.statusCode).toBe(400);
		expect(res.json()).toMatchObject({
			error: "chain-required",
			servedChainIds: [31337, 31338],
		});
	});

	it("refuses an unserved chain with the served list (MC-52)", async () => {
		const res = await ctx.app.inject({
			method: "POST",
			url: "/v1/userops",
			headers: { authorization: `Bearer ${sessionToken}` },
			payload: { chainId: 10, userOperation: makeOp(3) },
		});
		expect(res.statusCode).toBe(400);
		expect(res.json()).toMatchObject({
			error: "unsupported-chain",
			servedChainIds: [31337, 31338],
		});
	});

	it("the JSON-RPC bundler relay routes by the chain in its PATH, to that chain's bundler (MC-58)", async () => {
		const entryPoint = "0x433709009B8330FDa32311DF1C2AFA402eD8D009";
		const relay = (url: string, method: string, params: unknown[] = []) =>
			ctx.app.inject({
				method: "POST",
				url,
				headers: { authorization: `Bearer ${sessionToken}` },
				payload: { jsonrpc: "2.0", id: 1, method, params },
			});

		const onA = await relay("/v1/bundler/31337", "eth_sendUserOperation", [
			makeOp(4),
			entryPoint,
		]);
		const onB = await relay("/v1/bundler/31338", "eth_sendUserOperation", [
			makeOp(4),
			entryPoint,
		]);
		const hashA = (onA.json() as { result: string }).result;
		const hashB = (onB.json() as { result: string }).result;
		expect(hashA).toMatch(/^0x[0-9a-f]{64}$/);
		expect(hashA).not.toBe(hashB); // the hash commits to the chain (MC-57)

		const sends = ctx.bundlerCalls
			.filter((call) => call.method === "eth_sendUserOperation")
			.slice(-2);
		expect(sends.map((call) => call.url)).toEqual([
			CHAIN_A_BUNDLER,
			CHAIN_B_BUNDLER,
		]);

		// the locally-answered methods answer for the chain in the path, too
		expect(
			(await relay("/v1/bundler/31338", "eth_chainId")).json(),
		).toMatchObject({ result: "0x7a6a" });

		// and a relay URL naming no chain is ambiguous here, exactly like an omitted chainId (MC-53)
		const bare = await relay("/v1/bundler", "eth_chainId");
		expect(bare.statusCode).toBe(400);
		expect(bare.json()).toMatchObject({
			error: "chain-required",
			servedChainIds: [31337, 31338],
		});

		// the read relay routes the same way, tenant-bound by Origin
		const read = await ctx.app.inject({
			method: "POST",
			url: "/v1/rpc/31338",
			headers: { origin: TENANT_A.walletOrigin },
			payload: { jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] },
		});
		expect(read.json()).toMatchObject({ result: "0x7a6a" });
	});

	it("reports both chains on /v1/version, with no privileged one (MC-56)", async () => {
		const res = await ctx.app.inject({ method: "GET", url: "/v1/version" });
		const body = res.json() as {
			chainId: number | null;
			chains: Array<{ chainId: number }>;
		};
		expect(body.chainId).toBeNull();
		expect(body.chains.map((chain) => chain.chainId)).toEqual([31337, 31338]);
	});

	it("reports the release version the SDK packages carry on /v1/version", async () => {
		// A dApp's preflight warns when its connector is ahead of this. Reporting anything but the
		// shared release version made every SDK look ahead of the api.
		const res = await ctx.app.inject({ method: "GET", url: "/v1/version" });
		expect((res.json() as { version: string }).version).toBe(
			connectorPackage.version,
		);
	});
});
