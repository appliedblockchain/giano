/**
 * deployCore's signing paths and the deployment record (openspec: production-key-ceremony,
 * contract-deployment). The chain is a stub that holds the real runtime code of the baked devnet
 * (e2e/devnet/state.json), so "already deployed" is checked against the release fingerprints.
 *
 *   pnpm --filter @appliedblockchain/giano-contracts test:deploy
 */
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { describe, it } from "node:test";
import { type Address, type Hex, keccak256, type PublicClient } from "viem";
import { DEPLOYERS } from "./config";

const CANONICAL_DEPLOYER = DEPLOYERS.local;

import {
	CREATEX_ADDRESS,
	create3Address,
	create3Salt,
	guardedSalt,
} from "./create3";
import {
	type DeployContext,
	deployCore,
	deployTesting,
	privateTestErc20Wanted,
} from "./deploy";
import { recordDeviations } from "./records";
import { loadRelease, type Release } from "./release";

const LABELS = [
	"giano.wallet.impl",
	"giano.factory",
	"giano.paymaster.impl",
	"giano.paymaster.proxy",
];
const ADDRESSES = LABELS.map((l) => create3Address(CANONICAL_DEPLOYER, l));

const state = JSON.parse(
	fs.readFileSync(
		path.resolve(import.meta.dirname, "../../../e2e/devnet/state.json"),
		"utf8",
	),
) as { accounts: Record<string, { code: Hex }> };
const devnetCode = (address: Address): Hex =>
	state.accounts[address.toLowerCase()].code;

const PAYMASTER = {
	entryPoint: "0x0000000071727De22E5E9d8BAf0edAc6f37da032" as Address,
	roleAdmin: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" as Address,
	defaultFeeWei: 1n,
	postOpGasAllowance: 40_000,
	penaltyBps: 1000,
};

/** A chain stub: `code` per address, CreateX's address math, and a log of what was sent. */
function chain(code: Map<string, Hex>) {
	const sent: string[] = [];
	const create3 = new Map(
		LABELS.map((l) => [
			guardedSalt(CANONICAL_DEPLOYER, create3Salt(CANONICAL_DEPLOYER, l)),
			create3Address(CANONICAL_DEPLOYER, l),
		]),
	);
	const publicClient = {
		getCode: async ({ address }: { address: Address }) =>
			address === CREATEX_ADDRESS ? "0x01" : (code.get(address) ?? "0x"),
		readContract: async ({ args }: { args: [Hex] }) => create3.get(args[0]),
		simulateContract: async ({ args }: { args: [Hex] }) => {
			const label = LABELS.find(
				(l) => create3Salt(CANONICAL_DEPLOYER, l) === args[0],
			) as string;
			return {
				request: { label },
				result: create3Address(CANONICAL_DEPLOYER, label),
			};
		},
		waitForTransactionReceipt: async () => ({ status: "success" }),
	} as unknown as PublicClient;
	const walletClient = {
		account: { address: CANONICAL_DEPLOYER },
		writeContract: async ({ label }: { label: string }) => {
			sent.push(label);
			const address = create3Address(CANONICAL_DEPLOYER, label);
			code.set(address, devnetCode(address));
			return keccak256(`0x${Buffer.from(label).toString("hex")}`);
		},
	} as unknown as DeployContext["walletClient"];
	return { publicClient, walletClient, sent };
}

const context = (
	publicClient: PublicClient,
	walletClient?: DeployContext["walletClient"],
): DeployContext => ({
	publicClient,
	walletClient,
	deployer: CANONICAL_DEPLOYER,
	network: "local",
	record: {
		chainId: 31337,
		deployer: CANONICAL_DEPLOYER,
		contracts: {},
		upgrades: [],
	},
	log: () => {},
});

const allDeployed = () =>
	new Map<string, Hex>(ADDRESSES.map((a) => [a, devnetCode(a)]));

describe("deployCore without a key (verify only)", () => {
	it("verifies and records a chain that has every contract, sending nothing", async () => {
		const { publicClient, sent } = chain(allDeployed());
		const ctx = context(publicClient);
		await deployCore(ctx, loadRelease("v1"), PAYMASTER);
		assert.deepEqual(sent, []);
		assert.deepEqual(
			Object.values(ctx.record.contracts).map((c) => c?.address),
			ADDRESSES,
		);
	});

	it("fails on a contract that is missing, without asking for the key in a client deployment", async () => {
		const code = allDeployed();
		code.delete(ADDRESSES[1]);
		const { publicClient } = chain(code);
		await assert.rejects(
			deployCore(context(publicClient), loadRelease("v1"), PAYMASTER),
			/giano\.factory is not deployed .* no deployer key.*development team.*never put that key in a client deployment/,
		);
	});

	it("fails on an address holding code that matches no release", async () => {
		const code = allDeployed();
		code.set(ADDRESSES[0], "0x6080604052");
		const { publicClient } = chain(code);
		await assert.rejects(
			deployCore(context(publicClient), loadRelease("v1"), PAYMASTER),
			/giano\.wallet\.impl at .* matches no release's GianoSmartWallet/,
		);
	});

	it("records the release the code matches, its fingerprint and that it is deterministic", async () => {
		const { publicClient } = chain(allDeployed());
		const ctx = context(publicClient);
		await deployCore(ctx, loadRelease("v3"), PAYMASTER);
		assert.equal(ctx.record.network, "local");
		for (const [i, deployed] of Object.values(ctx.record.contracts).entries()) {
			assert.equal(deployed?.release, "v3");
			assert.match(deployed?.fingerprint ?? "", /^0x[0-9a-f]{64}$/);
			assert.equal(deployed?.expected, ADDRESSES[i]);
			assert.equal(deployed?.deterministic, true);
		}
	});
});

describe("deployCore with a key", () => {
	it("verifies an overridden paymaster where it is, deploys the rest, and records the confirmed deviation", async () => {
		const overridden = "0x3000000000000000000000000000000000000003" as Address;
		const code = new Map<string, Hex>([[overridden, devnetCode(ADDRESSES[3])]]);
		const { publicClient, walletClient, sent } = chain(code);
		const ctx = context(publicClient, walletClient);
		await deployCore(ctx, loadRelease("v3"), PAYMASTER, {
			paymasterProxy: overridden,
		});
		assert.deepEqual(sent, [
			"giano.wallet.impl",
			"giano.factory",
			"giano.paymaster.impl",
		]);
		recordDeviations(
			ctx.record,
			[
				{
					key: "paymasterProxy",
					reason: "override",
					expected: ADDRESSES[3],
					actual: overridden,
				},
			],
			true,
			"2026-11-03T00:00:00.000Z",
		);
		const { contracts, deviations } = ctx.record;
		assert.equal(contracts.paymasterProxy?.address, overridden);
		assert.equal(contracts.paymasterProxy?.deterministic, false);
		assert.equal(contracts.paymasterProxy?.expected, ADDRESSES[3]);
		assert.equal(contracts.paymasterProxy?.transactionHash, undefined);
		for (const key of [
			"walletImplementation",
			"factory",
			"paymasterImplementation",
		] as const)
			assert.equal(contracts[key]?.deterministic, true, key);
		assert.deepEqual(deviations, [
			{
				contract: "paymasterProxy",
				reason: "override",
				expected: ADDRESSES[3],
				actual: overridden,
				at: "2026-11-03T00:00:00.000Z",
				confirmed: true,
			},
		]);
	});

	it("refuses an overridden contract with no code instead of deploying it", async () => {
		const { publicClient, walletClient, sent } = chain(new Map());
		await assert.rejects(
			deployCore(
				context(publicClient, walletClient),
				loadRelease("v3"),
				PAYMASTER,
				{
					walletImplementation: "0x3000000000000000000000000000000000000003",
				},
			),
			/fixed at 0x3000000000000000000000000000000000000003, which has no code/,
		);
		assert.deepEqual(sent, []);
	});

	it("deploys what is missing and only that", async () => {
		const code = allDeployed();
		code.delete(ADDRESSES[1]);
		code.delete(ADDRESSES[3]);
		const { publicClient, walletClient, sent } = chain(code);
		await deployCore(
			context(publicClient, walletClient),
			loadRelease("v1"),
			PAYMASTER,
		);
		assert.deepEqual(sent, ["giano.factory", "giano.paymaster.proxy"]);
	});
});

describe("deployTesting and the private test token (silent-data-network D7)", () => {
	const TESTING_LABELS = [
		"giano.test.erc20",
		"giano.test.paymaster",
		"giano.test.private-erc20",
	];
	const PRIVATE_TOKEN = create3Address(
		CANONICAL_DEPLOYER,
		"giano.test.private-erc20",
	);
	const PARAMS = {
		holder: PAYMASTER.roleAdmin,
		owner: PAYMASTER.roleAdmin,
		entryPoint: PAYMASTER.entryPoint,
		fundWei: 0n,
	};

	/** A `dev` release (accepted without a fingerprint, as on a local chain), with or without the token. */
	const devRelease = (withPrivateToken: boolean): Release => {
		const contracts: Record<string, { source: string; creationCode: Hex }> = {
			PrivateERC20: { source: "", creationCode: "0x01" },
			PermissivePaymaster: { source: "", creationCode: "0x02" },
		};
		if (withPrivateToken)
			contracts.GianoTestPrivateErc20 = { source: "", creationCode: "0x03" };
		return {
			version: "dev",
			compiler: { solc: "test", settings: {} },
			contracts: contracts as Release["contracts"],
		};
	};

	/** Like `chain`, for the testing labels: every deployment leaves some code at its address. */
	function testingChain() {
		const code = new Map<string, Hex>();
		const sent: string[] = [];
		const salts = new Map(
			TESTING_LABELS.map((l) => [
				guardedSalt(CANONICAL_DEPLOYER, create3Salt(CANONICAL_DEPLOYER, l)),
				create3Address(CANONICAL_DEPLOYER, l),
			]),
		);
		const publicClient = {
			getCode: async ({ address }: { address: Address }) =>
				address === CREATEX_ADDRESS ? "0x01" : (code.get(address) ?? "0x"),
			readContract: async ({ args }: { args: [Hex] }) => salts.get(args[0]),
			simulateContract: async ({ args }: { args: [Hex] }) => {
				const label = TESTING_LABELS.find(
					(l) => create3Salt(CANONICAL_DEPLOYER, l) === args[0],
				) as string;
				return {
					request: { label },
					result: create3Address(CANONICAL_DEPLOYER, label),
				};
			},
			waitForTransactionReceipt: async () => ({ status: "success" }),
		} as unknown as PublicClient;
		const walletClient = {
			account: { address: CANONICAL_DEPLOYER },
			writeContract: async ({ label }: { label: string }) => {
				sent.push(label);
				code.set(create3Address(CANONICAL_DEPLOYER, label), "0x6001");
				return keccak256(`0x${Buffer.from(label).toString("hex")}`);
			},
		} as unknown as DeployContext["walletClient"];
		return { publicClient, walletClient, sent };
	}

	it("deploys GianoTestPrivateErc20 under giano.test.private-erc20 when asked, and records it", async () => {
		const { publicClient, walletClient, sent } = testingChain();
		const ctx = context(publicClient, walletClient);
		await deployTesting(ctx, devRelease(true), {
			...PARAMS,
			privateTestErc20: true,
		});
		assert.deepEqual(sent, TESTING_LABELS);
		assert.equal(ctx.record.contracts.privateTestErc20?.address, PRIVATE_TOKEN);
		assert.equal(
			ctx.record.contracts.privateTestErc20?.label,
			"giano.test.private-erc20",
		);
		assert.equal(ctx.record.contracts.privateTestErc20?.deterministic, true);
	});

	it("leaves it out when not asked, even if the release carries it", async () => {
		const { publicClient, walletClient, sent } = testingChain();
		const ctx = context(publicClient, walletClient);
		await deployTesting(ctx, devRelease(true), PARAMS);
		assert.deepEqual(sent, ["giano.test.erc20", "giano.test.paymaster"]);
		assert.equal(ctx.record.contracts.privateTestErc20, undefined);
	});

	it("refuses a release that predates the token before sending anything", async () => {
		const { publicClient, walletClient, sent } = testingChain();
		await assert.rejects(
			deployTesting(context(publicClient, walletClient), devRelease(false), {
				...PARAMS,
				privateTestErc20: true,
			}),
			/release dev predates GianoTestPrivateErc20/,
		);
		assert.deepEqual(sent, []);
	});

	it("a remote chain gets it only when its profile opts in", () => {
		const remote = { local: false, profileId: "copper-heron" };
		assert.equal(privateTestErc20Wanted(devRelease(true), remote), false);
		assert.equal(
			privateTestErc20Wanted(devRelease(true), { ...remote, optIn: false }),
			false,
		);
		assert.equal(
			privateTestErc20Wanted(devRelease(true), { ...remote, optIn: true }),
			true,
		);
		// A release without the token: nothing to opt out of, so no error without the opt-in.
		assert.equal(privateTestErc20Wanted(loadRelease("v3"), remote), false);
	});

	it("a profile that opts in with a release that predates the token is refused", () => {
		assert.throws(
			() =>
				privateTestErc20Wanted(loadRelease("v3"), {
					local: false,
					profileId: "copper-heron",
					optIn: true,
				}),
			/profile copper-heron enables privateTestErc20, but release v3 predates GianoTestPrivateErc20/,
		);
	});

	it("a local chain gets it whenever the release carries it", () => {
		assert.equal(
			privateTestErc20Wanted(devRelease(true), { local: true }),
			true,
		);
		assert.equal(
			privateTestErc20Wanted(loadRelease("v3"), { local: true }),
			false,
		);
	});
});
