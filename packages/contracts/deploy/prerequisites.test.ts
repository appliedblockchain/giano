/**
 * What a chain must offer before Giano is deployed on it (deploy/preflight.ts chainPrerequisites), the
 * network class a mainnet can never lose (deploy/config.ts assertNetworkClass), and the doctor's
 * P-256 line (deploy/p256.ts p256Report).
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { type Hex, keccak256, type PublicClient } from "viem";
import { entryPointRuntimeCode } from "../entrypoint";
import {
	assertNetworkClass,
	ENTRY_POINT_V09,
	isMainnetChain,
	isProductionChain,
	MAINNET_CHAIN_IDS,
	redactRpcUrl,
} from "./config";
import { CREATEX_ADDRESS } from "./create3";
import { p256Report } from "./p256";
import {
	CREATEX_CODEHASH,
	chainPrerequisites,
	isContractAccount,
} from "./preflight";
import { loadProfile, REPO_ROOT } from "./profiles";

test("every mainnet is a production chain, so the test fixtures can never reach one (R-29)", () => {
	for (const chainId of MAINNET_CHAIN_IDS) {
		assert.equal(isProductionChain(chainId), true, `chain ${chainId}`);
		assert.equal(isMainnetChain(chainId), true, `chain ${chainId}`);
	}
	// Ethereum mainnet has no profile: --network testnet must not be able to declare it one.
	assert.equal(isProductionChain(1, "testnet"), true);
});

test("a chain on the mainnet list can never be treated as a testnet", () => {
	assert.throws(() => assertNetworkClass(1, "testnet"), /chain 1 is a mainnet/);
	assert.throws(() => assertNetworkClass(8453, "local"), /is a mainnet/);
	assertNetworkClass(1, "mainnet");
	assertNetworkClass(84532, "testnet");
});

test("a profile declaring a mainnet-list chain testnet is refused when it loads", () => {
	const dir = mkdtempSync(join(tmpdir(), "profiles-"));
	try {
		const shipped = JSON.parse(
			readFileSync(join(REPO_ROOT, "deploy/chains/base-sepolia.json"), "utf8"),
		);
		const file = join(dir, "ethereum.json");
		writeFileSync(
			file,
			JSON.stringify({ ...shipped, chainId: 1, name: "Ethereum" }),
		);
		assert.throws(() => loadProfile({ config: file }), /chain 1 is a mainnet/);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

/** A chain whose CreateX, EntryPoint and Cancun support are as given. */
function chain(options: {
	createX?: Hex;
	entryPoint?: Hex;
	cancun?: boolean;
	chainId?: number;
}): PublicClient {
	return {
		getCode: async ({ address }: { address: string }) =>
			address === CREATEX_ADDRESS
				? options.createX
				: address === ENTRY_POINT_V09
					? options.entryPoint
					: undefined,
		call: async () => {
			if (options.cancun === false) throw new Error("invalid opcode: TLOAD");
			return { data: "0x" };
		},
	} as unknown as PublicClient;
}

test("chain prerequisites: CreateX by its upstream codehash, the canonical EntryPoint, Cancun", async () => {
	const chainId = 84532;
	const entryPoint = entryPointRuntimeCode(chainId);
	// No fixture carries the real CreateX runtime, so its codehash check is exercised by mismatch.
	const foreign = await chainPrerequisites(
		chain({ createX: "0x6001", entryPoint, cancun: true }),
		chainId,
	);
	const createX = foreign.find((p) => p.name.startsWith("CreateX"));
	assert.equal(createX?.ok, false);
	assert.match(createX?.detail ?? "", /unrecognised runtime/);
	assert.match(createX?.detail ?? "", new RegExp(CREATEX_CODEHASH));
	assert.notEqual(keccak256("0x6001"), CREATEX_CODEHASH);
	assert.equal(foreign.find((p) => p.name.startsWith("EntryPoint"))?.ok, true);

	const bare = await chainPrerequisites(chain({ cancun: false }), chainId);
	assert.deepEqual(
		bare.map((p) => p.ok),
		[false, false, false],
	);
	assert.match(
		bare.find((p) => p.name.startsWith("Cancun"))?.detail ?? "",
		/compiled for Cancun/,
	);
});

test("a chain with no P-256 precompile and no shared verifier is informational, never a failure", () => {
	assert.equal(p256Report("none").level, "info");
	assert.match(p256Report("none").detail, /passkey checks work/);
	assert.equal(p256Report("precompile").level, "ok");
	assert.equal(p256Report("verifier").level, "ok");
});

test("a contract account has real code; no code or an EIP-7702 designator is a key", () => {
	assert.equal(isContractAccount(undefined), false);
	assert.equal(isContractAccount("0x"), false);
	assert.equal(
		isContractAccount(`0xef0100${"ab".repeat(20)}`),
		false,
		"an EIP-7702 delegated EOA",
	);
	assert.equal(isContractAccount("0x6080604052"), true);
	// Longer than a designator: real code that merely starts with the same bytes.
	assert.equal(isContractAccount(`0xef0100${"ab".repeat(21)}`), true);
});

test("an RPC URL is printed as its origin only", () => {
	assert.equal(
		redactRpcUrl("https://example-node.provider.com/abc123secret/"),
		"https://example-node.provider.com",
	);
	assert.equal(
		redactRpcUrl("https://user:pass@node.example.com:8545/v1?key=abc123secret"),
		"https://node.example.com:8545",
	);
	assert.doesNotMatch(redactRpcUrl("not a url abc123secret"), /abc123secret/);
});

test("deploy:cli never prints a keyed RPC URL, not even in a provider error", () => {
	const run = spawnSync(
		process.execPath,
		[
			"--import",
			"tsx",
			"deploy/cli.ts",
			"core",
			"--rpc",
			"http://127.0.0.1:1/abc123secret",
			"--chain",
			"base-sepolia",
			"--role-admin",
			"0x0000000000000000000000000000000000000001",
		],
		{ cwd: join(import.meta.dirname, ".."), encoding: "utf8" },
	);
	assert.notEqual(run.status, 0);
	assert.doesNotMatch(`${run.stdout}${run.stderr}`, /abc123secret/);
	assert.match(`${run.stdout}${run.stderr}`, /http:\/\/127\.0\.0\.1:1/);
});
