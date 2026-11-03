/**
 * The deployment plan and the mainnet deviation gate (openspec: contract-deployment). The chain is a
 * stub holding real v2 runtime code from the baked devnet (e2e/devnet/state.json); release
 * fingerprints mask immutables, so that code passes as release code at any address.
 */
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { describe, it } from "node:test";
import {
	type Address,
	getAddress,
	type Hex,
	type PublicClient,
	pad,
} from "viem";
import { DEPLOYERS, LABELS } from "./config";
import { create3Address } from "./create3";
import {
	CORE_KEYS,
	type CoreKey,
	deviationGate,
	deviationWarning,
	fixedAddresses,
	IMPLEMENTATION_SLOT,
	planCore,
} from "./plan";

const state = JSON.parse(
	fs.readFileSync(
		path.resolve(import.meta.dirname, "../../../e2e/devnet/state.json"),
		"utf8",
	),
) as { accounts: Record<string, { code: Hex }> };
/** v2 runtime code of each core contract, as the devnet holds it under the local deployer. */
const CODE = Object.fromEntries(
	CORE_KEYS.map((key) => [
		key,
		state.accounts[create3Address(DEPLOYERS.local, LABELS[key]).toLowerCase()]
			.code,
	]),
) as Record<CoreKey, Hex>;

/** A stand-in mainnet canonical deployer (DEPLOYERS.mainnet is not configured yet). */
const MAINNET = getAddress("0x1000000000000000000000000000000000000001");
const OTHER_KEY = getAddress("0x2000000000000000000000000000000000000002");
const expected = (key: CoreKey, deployer: Address = MAINNET) =>
	create3Address(deployer, LABELS[key]);

/**
 * A chain stub. `code` per address; the factory reports `implementation`, and the proxy's slot
 * holds `paymasterImplementation`.
 */
function chain(
	code: Record<string, Hex>,
	{
		implementation,
		paymasterImplementation,
	}: { implementation?: Address; paymasterImplementation?: Address } = {},
): PublicClient {
	const lookup = new Map(
		Object.entries(code).map(([a, c]) => [a.toLowerCase(), c]),
	);
	return {
		getCode: async ({ address }: { address: Address }) =>
			lookup.get(address.toLowerCase()) ?? "0x",
		readContract: async () => implementation,
		getStorageAt: async ({ slot }: { slot: Hex }) => {
			assert.equal(slot, IMPLEMENTATION_SLOT);
			return paymasterImplementation
				? pad(paymasterImplementation)
				: pad("0x00");
		},
	} as unknown as PublicClient;
}

/** Every core contract deployed at `deployer`'s CREATE3 addresses, consistently wired. */
function deployedBy(deployer: Address) {
	const code: Record<string, Hex> = {};
	for (const key of CORE_KEYS) code[expected(key, deployer)] = CODE[key];
	return chain(code, {
		implementation: expected("walletImplementation", deployer),
		paymasterImplementation: expected("paymasterImplementation", deployer),
	});
}

describe("planCore", () => {
	it("plans the class's deterministic addresses with no deviation for the canonical signer", async () => {
		const plan = await planCore(chain({}), {
			network: "mainnet",
			signer: MAINNET,
			deployer: MAINNET,
		});
		assert.deepEqual(plan.blockers, []);
		assert.deepEqual(plan.deviations, []);
		for (const c of plan.contracts) {
			assert.equal(c.actual, expected(c.key as CoreKey));
			assert.equal(c.expected, c.actual);
			assert.equal(c.code.state, "empty");
		}
	});

	it("classifies every contract another key would deploy as a non-canonical-signer deviation", async () => {
		const plan = await planCore(chain({}), {
			network: "mainnet",
			signer: OTHER_KEY,
			deployer: MAINNET,
		});
		assert.deepEqual(plan.blockers, []);
		assert.deepEqual(
			plan.deviations.map((d) => [d.key, d.reason, d.expected, d.actual]),
			CORE_KEYS.map((key) => [
				key,
				"non-canonical-signer",
				expected(key),
				expected(key, OTHER_KEY),
			]),
		);
	});

	it("reuses contracts already at the expected addresses, whoever signs", async () => {
		const plan = await planCore(deployedBy(MAINNET), {
			network: "mainnet",
			signer: OTHER_KEY,
			deployer: MAINNET,
			release: "v2",
		});
		assert.deepEqual(plan.blockers, []);
		assert.deepEqual(plan.deviations, []);
		assert.deepEqual(
			fixedAddresses(plan),
			Object.fromEntries(CORE_KEYS.map((key) => [key, expected(key)])),
		);
	});

	it("verifies an override holding release code and reports it as an override deviation", async () => {
		const proxy = getAddress("0x3000000000000000000000000000000000000003");
		const implementation = expected("paymasterImplementation");
		const plan = await planCore(
			chain(
				{
					[proxy]: CODE.paymasterProxy,
					[implementation]: CODE.paymasterImplementation,
				},
				{ paymasterImplementation: implementation },
			),
			{
				network: "mainnet",
				signer: MAINNET,
				deployer: MAINNET,
				overrides: { paymasterProxy: proxy },
			},
		);
		assert.deepEqual(plan.blockers, []);
		assert.deepEqual(plan.deviations, [
			{
				key: "paymasterProxy",
				reason: "override",
				expected: expected("paymasterProxy"),
				actual: proxy,
			},
		]);
		assert.equal(fixedAddresses(plan).paymasterProxy, proxy);
	});

	it("refuses an override with no code before signing", async () => {
		const factory = getAddress("0x4000000000000000000000000000000000000004");
		const plan = await planCore(chain({}), {
			network: "testnet",
			signer: MAINNET,
			deployer: MAINNET,
			overrides: { factory },
		});
		assert.ok(
			plan.blockers.some(
				(b) => b.includes(`factory at ${factory}`) && /has no code/.test(b),
			),
			plan.blockers.join("\n"),
		);
	});

	it("refuses an override holding foreign code before signing", async () => {
		const factory = getAddress("0x4000000000000000000000000000000000000004");
		const plan = await planCore(
			// The wallet implementation's code is a release's, but not a factory's.
			chain({ [factory]: CODE.walletImplementation }),
			{
				network: "testnet",
				signer: MAINNET,
				deployer: MAINNET,
				overrides: { factory },
			},
		);
		assert.ok(
			plan.blockers.some(
				(b) =>
					b.includes(`factory at ${factory}`) &&
					/matches no release's GianoSmartWalletFactory/.test(b),
			),
			plan.blockers.join("\n"),
		);
	});

	it("reports a contract the record lists away from its expected address as existing-elsewhere", async () => {
		const wallet = getAddress("0x5000000000000000000000000000000000000005");
		const plan = await planCore(
			chain({ [wallet]: CODE.walletImplementation }),
			{
				network: "mainnet",
				signer: MAINNET,
				deployer: MAINNET,
				record: {
					chainId: 8453,
					deployer: OTHER_KEY,
					contracts: {
						walletImplementation: {
							address: wallet,
							label: LABELS.walletImplementation,
							release: "v2",
							codehash: "0x00",
						},
					},
					upgrades: [],
				},
			},
		);
		assert.deepEqual(
			plan.deviations.map((d) => [d.key, d.reason, d.actual]),
			[["walletImplementation", "existing-elsewhere", wallet]],
		);
		assert.equal(fixedAddresses(plan).walletImplementation, wallet);
	});

	it("refuses foreign code at an expected address", async () => {
		const plan = await planCore(
			chain({ [expected("factory")]: "0x6080604052" }),
			{ network: "mainnet", signer: MAINNET, deployer: MAINNET },
		);
		assert.ok(plan.blockers.some((b) => /occupied by code/.test(b)));
	});

	it("refuses an existing factory bound to another wallet implementation", async () => {
		const code = { [expected("factory")]: CODE.factory };
		const plan = await planCore(chain(code, { implementation: OTHER_KEY }), {
			network: "mainnet",
			signer: MAINNET,
			deployer: MAINNET,
		});
		assert.ok(
			plan.blockers.some((b) =>
				b.includes(`clones the wallet implementation ${OTHER_KEY}`),
			),
			plan.blockers.join("\n"),
		);
	});

	it("verifies a timelock override as GianoTimelock release code", async () => {
		const timelock = getAddress("0x6000000000000000000000000000000000000006");
		const plan = await planCore(chain({ [timelock]: CODE.factory }), {
			network: "testnet",
			signer: MAINNET,
			deployer: MAINNET,
			overrides: { timelock },
		});
		assert.ok(
			plan.blockers.some((b) =>
				/timelock at .* matches no release's GianoTimelock/.test(b),
			),
		);
	});

	it("still plans, but blocks signing, while the class deployer is not configured", async () => {
		const plan = await planCore(chain({}), {
			network: "mainnet",
			signer: OTHER_KEY,
			deployer: null,
		});
		assert.match(
			plan.blockers.join("\n"),
			/mainnet canonical deployer is not configured/,
		);
		assert.equal(plan.contracts.length, CORE_KEYS.length);
		for (const c of plan.contracts) assert.equal(c.expected, null);
	});
});

describe("deviationGate", () => {
	const plan = (network: "mainnet" | "testnet", signer: Address) =>
		planCore(chain({}), { network, signer, deployer: MAINNET });

	it("a canonical mainnet run needs only the usual confirmation", async () => {
		assert.deepEqual(
			deviationGate(await plan("mainnet", MAINNET), "base", {
				interactive: true,
			}),
			{ kind: "none" },
		);
	});

	it("a mainnet run with another key needs the typed deviation phrase", async () => {
		const p = await plan("mainnet", OTHER_KEY);
		assert.deepEqual(deviationGate(p, "base", { interactive: true }), {
			kind: "confirm",
			phrase: "deviate base",
		});
		const warning = deviationWarning(p, "Base").join("\n");
		for (const key of CORE_KEYS) {
			assert.ok(warning.includes(expected(key)), key);
			assert.ok(warning.includes(expected(key, OTHER_KEY)), key);
		}
		assert.match(warning, /differ from the other mainnet chains, permanently/);
	});

	it("a non-interactive mainnet run refuses any deviation and lists them", async () => {
		const gate = deviationGate(await plan("mainnet", OTHER_KEY), "base", {
			interactive: false,
		});
		assert.equal(gate.kind, "refuse");
		assert.match(
			gate.kind === "refuse" ? gate.reason : "",
			/walletImplementation: non-canonical-signer.*paymasterProxy: non-canonical-signer/,
		);
	});

	it("--allow-deviation lets a non-interactive mainnet run through", async () => {
		assert.deepEqual(
			deviationGate(await plan("mainnet", OTHER_KEY), "base", {
				interactive: false,
				allowDeviation: true,
			}),
			{ kind: "none" },
		);
	});

	it("a testnet override is reported, not gated", async () => {
		const proxy = getAddress("0x3000000000000000000000000000000000000003");
		const implementation = expected("paymasterImplementation");
		const p = await planCore(
			chain(
				{
					[proxy]: CODE.paymasterProxy,
					[implementation]: CODE.paymasterImplementation,
				},
				{ paymasterImplementation: implementation },
			),
			{
				network: "testnet",
				signer: MAINNET,
				deployer: MAINNET,
				overrides: { paymasterProxy: proxy },
			},
		);
		assert.equal(p.deviations.length, 1);
		assert.deepEqual(deviationGate(p, "base-sepolia", { interactive: false }), {
			kind: "none",
		});
	});
});
