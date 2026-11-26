/**
 * What a chain must offer before Giano is deployed on it (deploy/preflight.ts chainPrerequisites), the
 * network class a mainnet can never lose (deploy/config.ts assertNetworkClass), and the doctor's
 * P-256 line (deploy/p256.ts p256Report).
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
	createPublicClient,
	custom,
	type Hex,
	http,
	keccak256,
	type PublicClient,
} from "viem";
import { entryPointRuntimeCode } from "../entrypoint";
import {
	assertNetworkClass,
	ENTRY_POINT_V09,
	flaggedRpcUrls,
	isMainnetChain,
	isProductionChain,
	MAINNET_CHAIN_IDS,
	redactRpcUrl,
	redactRpcUrls,
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

/** A real viem client whose node has no CreateX or EntryPoint and answers `eth_call` with `error`. */
function node(error: { code: number; message: string }): PublicClient {
	return createPublicClient({
		transport: custom(
			{
				request: async ({ method }: { method: string }) => {
					if (method === "eth_getCode") return "0x";
					if (method === "eth_call") throw error;
					throw new Error(`unexpected ${method}`);
				},
			},
			{ retryCount: 0 },
		),
	}) as PublicClient;
}

const cancunOf = async (client: PublicClient) =>
	(await chainPrerequisites(client, 84532)).find((p) =>
		p.name.startsWith("Cancun"),
	)?.ok;

test("Cancun is unavailable only when the EVM itself refused the probe (G42 R2)", async () => {
	// anvil --hardfork shanghai, measured: InternalRpcError -32603 "EVM error NotActivated".
	assert.equal(
		await cancunOf(node({ code: -32603, message: "EVM error NotActivated" })),
		false,
	);
	// geth on a pre-Cancun chain.
	assert.equal(
		await cancunOf(
			node({
				code: -32000,
				message: "invalid opcode: opcode 0x5c not defined",
			}),
		),
		false,
	);
});

test("a rate limit, a rejected request, a revert or a dead endpoint is an RPC failure, not a missing Cancun (G42 R2)", async () => {
	// The probe has no REVERT, and viem files "gas required exceeds allowance" as a revert (#298 review).
	await assert.rejects(
		chainPrerequisites(node({ code: 3, message: "execution reverted" }), 84532),
	);
	await assert.rejects(
		chainPrerequisites(
			node({ code: -32000, message: "gas required exceeds allowance (0)" }),
			84532,
		),
	);
	await assert.rejects(
		chainPrerequisites(
			node({ code: -32005, message: "request rate exceeded" }),
			84532,
		),
	);
	// An RPC that refuses eth_call without `to`.
	await assert.rejects(
		chainPrerequisites(
			node({ code: -32602, message: "missing value for required argument to" }),
			84532,
		),
	);

	// HTTP 429, and an endpoint that never answers.
	const server = createServer((request, response) => {
		let body = "";
		request.on("data", (chunk) => {
			body += chunk;
		});
		request.on("end", () => {
			const { id, method } = JSON.parse(body);
			if (method === "eth_getCode") {
				response.setHeader("content-type", "application/json");
				response.end(JSON.stringify({ jsonrpc: "2.0", id, result: "0x" }));
			} else if (request.url === "/limited") {
				response.statusCode = 429;
				response.end("Too Many Requests");
			} else if (request.url === "/pre-cancun") {
				// A provider that sends the node's JSON-RPC error inside an HTTP 500 body.
				response.statusCode = 500;
				response.setHeader("content-type", "application/json");
				response.end(
					JSON.stringify({
						jsonrpc: "2.0",
						id,
						error: {
							code: -32000,
							message: "invalid opcode: opcode 0x5c not defined",
						},
					}),
				);
			}
			// "/silent": no answer at all.
		});
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const { port } = server.address() as AddressInfo;
	const over = (path: string) =>
		createPublicClient({
			transport: http(`http://127.0.0.1:${port}${path}`, {
				retryCount: 0,
				timeout: 200,
			}),
		}) as PublicClient;
	try {
		await assert.rejects(chainPrerequisites(over("/limited"), 84532));
		await assert.rejects(chainPrerequisites(over("/silent"), 84532));
		// ...but a missing opcode stays a missing opcode, whatever the HTTP status (#298 review).
		assert.equal(await cancunOf(over("/pre-cancun")), false);
	} finally {
		server.closeAllConnections();
		server.close();
	}
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

test("every given RPC URL is cut to its origin wherever an error quotes it", () => {
	const keyed = "https://base-sepolia.g.alchemy.com/v2/abc123secret";
	const message = `HTTP request failed.\n\nURL: ${keyed}\nRequest body: {}\nretry ${keyed}`;
	const redacted = redactRpcUrls(message, [undefined, keyed]);
	assert.doesNotMatch(redacted, /abc123secret/);
	assert.equal(
		redacted.match(/https:\/\/base-sepolia\.g\.alchemy\.com/g)?.length,
		2,
	);
	assert.equal(redactRpcUrls("no URL here", [keyed]), "no URL here");
});

test("every repeated --rpc value is redacted, not only the first", () => {
	const first = "https://node.example.com/v1/first-secret";
	const last = "https://node.example.com/v1/last-secret";
	const argv = ["node", "script.ts", "--rpc", first, "--plan", "--rpc", last];
	assert.deepEqual(flaggedRpcUrls(argv), [first, last]);
	assert.deepEqual(flaggedRpcUrls(["node", "script.ts", "--rpc"]), []);
	const redacted = redactRpcUrls(
		`request to ${last} failed`,
		flaggedRpcUrls(argv),
	);
	assert.doesNotMatch(redacted, /last-secret/);

	// A shorter URL that starts the same, given first, must not cut into the keyed one.
	const origin = "https://node.example.com/";
	const keyed = `${origin}v1/write-token`;
	assert.equal(
		redactRpcUrls(`request to ${keyed} failed`, [origin, keyed]),
		"request to https://node.example.com failed",
	);
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
