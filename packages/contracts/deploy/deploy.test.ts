/**
 * deployCore's three signing paths (openspec: production-key-ceremony). The chain is a stub that
 * holds the real runtime code of the baked devnet (e2e/devnet/state.json), so "already deployed"
 * is checked against the codehashes canonical.ts freezes.
 *
 *   pnpm --filter @appliedblockchain/giano-contracts test:deploy
 */
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { describe, it } from "node:test";
import { type Address, type Hex, keccak256, type PublicClient } from "viem";
import { CANONICAL_DEPLOYER } from "./config";
import {
	CREATEX_ADDRESS,
	create3Address,
	create3Salt,
	guardedSalt,
} from "./create3";
import { type DeployContext, deployCore } from "./deploy";
import { loadRelease } from "./release";

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
			/giano\.factory is not deployed .* no deployer key.*DevOps.*never put that key in a client deployment/,
		);
	});

	it("fails on a canonical address holding code no release puts there", async () => {
		const code = allDeployed();
		code.set(ADDRESSES[0], "0x6080604052");
		const { publicClient } = chain(code);
		await assert.rejects(
			deployCore(context(publicClient), loadRelease("v1"), PAYMASTER),
			/giano\.wallet\.impl at .* which no Giano release puts there/,
		);
	});
});

describe("deployCore with a key", () => {
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
