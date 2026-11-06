/**
 * The deployment plan and the mainnet deviation gate (openspec: contract-deployment). The chain is a
 * stub holding real v3 runtime code from the baked devnet (e2e/devnet/state.json); release
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
import { RELEASE_FINGERPRINTS } from "../release-code";
import { CONTRACT_OF, DEPLOYERS, LABELS, upgradeLabel } from "./config";
import { create3Address } from "./create3";
import {
	CORE_KEYS,
	type CoreKey,
	deviationGate,
	deviationWarning,
	fixedAddresses,
	IMPLEMENTATION_SLOT,
	planCore,
	upgradeDeviation,
} from "./plan";
import { type DeploymentRecord, recordDeviations } from "./records";

const state = JSON.parse(
	fs.readFileSync(
		path.resolve(import.meta.dirname, "../../../e2e/devnet/state.json"),
		"utf8",
	),
) as { accounts: Record<string, { code: Hex }> };
/** v3 runtime code of each core contract, as the devnet holds it under the local deployer. */
const CODE = Object.fromEntries(
	CORE_KEYS.map((key) => [
		key,
		state.accounts[create3Address(DEPLOYERS.local, LABELS[key]).toLowerCase()]
			.code,
	]),
) as Record<CoreKey, Hex>;

/**
 * `key`'s devnet code as it would be at `address`: its UUPS `__self` immutable set to `address`
 * (releaseOf refuses implementation code whose `__self` is another address).
 */
function place(key: CoreKey, address: Address): Hex {
	const fingerprint = RELEASE_FINGERPRINTS.find(
		(f) => f.contract === CONTRACT_OF[key] && f.release === "v3",
	);
	let code = CODE[key].toLowerCase();
	for (const { name, start, length } of fingerprint?.immutables ?? [])
		if (name.endsWith(".__self"))
			code =
				code.slice(0, 2 + start * 2) +
				address
					.slice(2)
					.toLowerCase()
					.padStart(length * 2, "0") +
				code.slice(2 + (start + length) * 2);
	return code as Hex;
}

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
	for (const key of CORE_KEYS)
		code[expected(key, deployer)] = place(key, expected(key, deployer));
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
			release: "v3",
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
					[implementation]: place("paymasterImplementation", implementation),
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
				acknowledged: false,
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
			chain({ [wallet]: place("walletImplementation", wallet) }),
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
							release: "v3",
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

	it("refuses an overridden proxy that points at another paymaster implementation", async () => {
		const proxy = getAddress("0x3000000000000000000000000000000000000003");
		const elsewhere = getAddress("0x7000000000000000000000000000000000000007");
		const plan = await planCore(
			chain(
				{
					[proxy]: CODE.paymasterProxy,
					[elsewhere]: place("paymasterImplementation", elsewhere),
				},
				{ paymasterImplementation: elsewhere },
			),
			{
				network: "testnet",
				signer: MAINNET,
				deployer: MAINNET,
				overrides: { paymasterProxy: proxy },
			},
		);
		assert.ok(
			plan.blockers.some((b) =>
				b.includes(`Override paymasterImplementation with ${elsewhere}`),
			),
			plan.blockers.join("\n"),
		);
	});

	it("refuses implementation code whose __self is another address", async () => {
		const wallet = getAddress("0x5000000000000000000000000000000000000005");
		const plan = await planCore(
			chain({ [wallet]: place("walletImplementation", OTHER_KEY) }),
			{
				network: "testnet",
				signer: MAINNET,
				deployer: MAINNET,
				overrides: { walletImplementation: wallet },
			},
		);
		assert.ok(
			plan.blockers.some(
				(b) =>
					b.includes(`walletImplementation at ${wallet}`) &&
					/matches no release's GianoSmartWallet/.test(b),
			),
			plan.blockers.join("\n"),
		);
	});

	it("a recorded contract away from its expected address must hold the selected release", async () => {
		const wallet = getAddress("0x5000000000000000000000000000000000000005");
		const plan = await planCore(
			chain({ [wallet]: place("walletImplementation", wallet) }),
			{
				network: "mainnet",
				signer: MAINNET,
				deployer: MAINNET,
				release: "v1",
				record: {
					chainId: 8453,
					deployer: OTHER_KEY,
					contracts: {
						walletImplementation: {
							address: wallet,
							label: LABELS.walletImplementation,
							release: "v3",
							codehash: "0x00",
						},
					},
					upgrades: [],
				},
			},
		);
		assert.ok(
			plan.blockers.some((b) =>
				b.includes(
					`walletImplementation at ${wallet} already holds release v3, not the selected v1`,
				),
			),
			plan.blockers.join("\n"),
		);
	});

	it("a local --release dev rerun accepts its own unreleased code", async () => {
		const deployer = DEPLOYERS.local;
		const unreleased = `0x${"60".repeat(64)}` as Hex;
		const code = Object.fromEntries(
			CORE_KEYS.map((key) => [expected(key, deployer), unreleased]),
		);
		const input = {
			network: "local" as const,
			signer: deployer,
			deployer,
		};
		const dev = await planCore(chain(code), { ...input, release: "dev" });
		assert.deepEqual(
			dev.blockers.filter((b) => /matches no release/.test(b)),
			[],
		);
		const released = await planCore(chain(code), { ...input, release: "v2" });
		assert.ok(released.blockers.some((b) => /matches no release/.test(b)));
	});

	it("a local --release dev run accepts release code already on the chain", async () => {
		const input = {
			network: "local" as const,
			signer: DEPLOYERS.local,
			deployer: DEPLOYERS.local,
		};
		const held = /already holds release/;
		const dev = await planCore(deployedBy(DEPLOYERS.local), {
			...input,
			release: "dev",
		});
		assert.deepEqual(
			dev.blockers.filter((b) => held.test(b)),
			[],
		);
		const v1 = await planCore(deployedBy(DEPLOYERS.local), {
			...input,
			release: "v1",
		});
		assert.ok(
			v1.blockers.some((b) => held.test(b)),
			v1.blockers.join("\n"),
		);
	});

	it("a verify-only run accepts existing code of any release", async () => {
		// The verify-only Helm Job selects the latest release unless told otherwise; a chain adopted at
		// an older one keeps it (the factory's implementation is immutable). A deployment, or a keyless
		// plan previewing one, still requires the selected release.
		const held = /already holds release/;
		const input = {
			network: "mainnet" as const,
			deployer: MAINNET,
			release: "v1",
		};
		const verify = await planCore(deployedBy(MAINNET), {
			...input,
			signer: null,
			verifyOnly: true,
		});
		assert.deepEqual(
			verify.blockers.filter((b) => held.test(b)),
			[],
		);
		for (const signer of [null, MAINNET]) {
			const deploy = await planCore(deployedBy(MAINNET), { ...input, signer });
			assert.ok(
				deploy.blockers.some((b) => held.test(b)),
				deploy.blockers.join("\n"),
			);
		}
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
				signs: true,
			}),
			{ kind: "none" },
		);
	});

	it("a mainnet run with another key needs the typed deviation phrase", async () => {
		const p = await plan("mainnet", OTHER_KEY);
		assert.deepEqual(
			deviationGate(p, "base", { interactive: true, signs: true }),
			{
				kind: "confirm",
				phrase: "deviate base",
			},
		);
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
			signs: true,
		});
		assert.equal(gate.kind, "refuse");
		assert.match(
			gate.kind === "refuse" ? gate.reason : "",
			/walletImplementation: non-canonical-signer.*paymasterProxy: non-canonical-signer/,
		);
	});

	it("a non-interactive mainnet run points at the guided wizard", async () => {
		const gate = deviationGate(await plan("mainnet", OTHER_KEY), "base", {
			interactive: false,
			signs: true,
		});
		assert.match(gate.kind === "refuse" ? gate.reason : "", /deploy:guided/);
	});

	it("a testnet override is reported, not gated", async () => {
		const proxy = getAddress("0x3000000000000000000000000000000000000003");
		const implementation = expected("paymasterImplementation");
		const p = await planCore(
			chain(
				{
					[proxy]: CODE.paymasterProxy,
					[implementation]: place("paymasterImplementation", implementation),
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
		assert.deepEqual(
			deviationGate(p, "base-sepolia", { interactive: false, signs: true }),
			{
				kind: "none",
			},
		);
	});
});

describe("deviations already in the record", () => {
	const wallet = getAddress("0x5000000000000000000000000000000000000005");
	const record = (confirmed: boolean): DeploymentRecord => ({
		chainId: 8453,
		deployer: OTHER_KEY,
		contracts: {
			walletImplementation: {
				address: wallet,
				label: LABELS.walletImplementation,
				release: "v3",
				codehash: "0x00",
			},
		},
		upgrades: [],
		deviations: [
			{
				contract: "walletImplementation",
				// Deployed by another key; a rerun now reads it as existing-elsewhere.
				reason: "non-canonical-signer",
				expected: expected("walletImplementation"),
				actual: wallet,
				at: "2026-11-01T00:00:00.000Z",
				confirmed,
			},
		],
	});
	const plan = (confirmed: boolean) =>
		planCore(chain({ [wallet]: place("walletImplementation", wallet) }), {
			network: "mainnet",
			signer: MAINNET,
			deployer: MAINNET,
			record: record(confirmed),
		});

	it("a deviation an operator confirmed is reported but not gated again", async () => {
		const p = await plan(true);
		assert.deepEqual(
			p.deviations.map((d) => [d.key, d.reason, d.acknowledged]),
			[["walletImplementation", "existing-elsewhere", true]],
		);
		assert.deepEqual(
			deviationGate(p, "base", { interactive: false, signs: true }),
			{ kind: "none" },
		);
		assert.match(
			deviationWarning(p, "Base").join("\n"),
			/already confirmed in the deployment record/,
		);
	});

	it("a deviation that was only reported still needs the typed confirmation", async () => {
		const p = await plan(false);
		assert.equal(
			deviationGate(p, "base", { interactive: false, signs: true }).kind,
			"refuse",
		);
		assert.equal(
			deviationGate(p, "base", { interactive: true, signs: true }).kind,
			"confirm",
		);
	});

	it("a run that signs nothing is never gated", async () => {
		const p = await planCore(chain({}), {
			network: "mainnet",
			signer: null,
			deployer: MAINNET,
			overrides: { factory: wallet },
		});
		assert.ok(p.deviations.length > 0);
		assert.deepEqual(
			deviationGate(p, "base", { interactive: false, signs: false }),
			{ kind: "none" },
		);
	});

	it("recordDeviations keeps one entry per contract and address, whatever the reason", () => {
		const r = record(false);
		recordDeviations(
			r,
			[
				{
					key: "walletImplementation",
					reason: "existing-elsewhere",
					expected: expected("walletImplementation"),
					actual: wallet,
				},
			],
			true,
		);
		assert.equal(r.deviations?.length, 1);
		assert.equal(r.deviations?.[0].reason, "non-canonical-signer");
		assert.equal(r.deviations?.[0].confirmed, true);
	});
});

describe("upgrade targets", () => {
	const label = upgradeLabel(LABELS.paymasterImplementation, "v3");
	const target = create3Address(MAINNET, label);
	const record = (address: Address): DeploymentRecord => ({
		chainId: 8453,
		deployer: MAINNET,
		contracts: {
			paymasterImplementation: {
				address,
				label,
				release: "v2",
				codehash: "0x00",
			},
		},
		upgrades: [
			{
				address,
				label,
				release: "v2",
				codehash: "0x00",
				of: "paymasterImplementation",
			},
		],
	});

	it("an implementation upgraded to its versioned deterministic address is expected there", async () => {
		const p = await planCore(
			chain({ [target]: place("paymasterImplementation", target) }),
			{
				network: "mainnet",
				signer: null,
				deployer: MAINNET,
				// Older than the upgrade: the upgraded implementation may hold a newer release.
				release: "v1",
				record: record(target),
			},
		);
		const planned = p.contracts.find(
			(c) => c.key === "paymasterImplementation",
		);
		assert.equal(planned?.expected, target);
		assert.equal(planned?.actual, target);
		assert.equal(planned?.label, label);
		assert.deepEqual(p.deviations, []);
		assert.deepEqual(
			p.blockers.filter((b) => b.includes("paymasterImplementation")),
			[],
		);
		assert.equal(fixedAddresses(p).paymasterImplementation, target);
	});

	it("an upgrade target deployed by another key stays a deviation", async () => {
		const elsewhere = create3Address(OTHER_KEY, label);
		const p = await planCore(
			chain({ [elsewhere]: place("paymasterImplementation", elsewhere) }),
			{
				network: "mainnet",
				signer: null,
				deployer: MAINNET,
				record: record(elsewhere),
			},
		);
		assert.deepEqual(
			p.deviations.map((d) => [d.key, d.reason, d.actual]),
			[["paymasterImplementation", "existing-elsewhere", elsewhere]],
		);
	});
});

describe("upgradeDeviation", () => {
	const label = upgradeLabel(LABELS.paymasterImplementation, "v3");

	it("the canonical deployer deploys an upgrade target where every chain has it", () => {
		assert.deepEqual(
			upgradeDeviation(
				"mainnet",
				MAINNET,
				MAINNET,
				"paymasterImplementation",
				label,
			),
			{ kind: "none" },
		);
	});

	it("another key is refused on a mainnet", () => {
		const check = upgradeDeviation(
			"mainnet",
			MAINNET,
			OTHER_KEY,
			"paymasterImplementation",
			label,
		);
		assert.equal(check.kind, "refuse");
		assert.match(
			check.kind === "refuse" ? check.reason : "",
			new RegExp(create3Address(OTHER_KEY, label)),
		);
	});

	it("another key on a testnet is recorded as a deviation", () => {
		const check = upgradeDeviation(
			"testnet",
			MAINNET,
			OTHER_KEY,
			"paymasterImplementation",
			label,
		);
		assert.equal(check.kind, "record");
		assert.deepEqual(check.kind === "record" ? check.deviation : undefined, {
			key: "paymasterImplementation",
			reason: "non-canonical-signer",
			expected: create3Address(MAINNET, label),
			actual: create3Address(OTHER_KEY, label),
		});
	});
});
