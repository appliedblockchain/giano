import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";
import { type Address, type Hex, type PublicClient, zeroAddress } from "viem";
import { DEPLOYERS, LABELS } from "./config";
import { create3Address } from "./create3";
import { planCore } from "./plan";
import { inspectDeployment, roleAdmin, verifyCoreState } from "./preflight";
import { loadProfile } from "./profiles";

const profile = loadProfile({ chain: "base-sepolia" }).profile;
/** Tests stand the local deployer in for the (not yet configured) testnet one. */
const CANONICAL_DEPLOYER = DEPLOYERS.local;
const options = { signer: null, deployer: CANONICAL_DEPLOYER };
const state = JSON.parse(
	readFileSync(
		resolve(import.meta.dirname, "../../../e2e/devnet/state.json"),
		"utf8",
	),
) as { accounts: Record<string, { code: Hex }> };
const devnetCode = (address: Address): Hex =>
	state.accounts[address.toLowerCase()].code;

const admin = "0x1111111111111111111111111111111111111111" as Address;
function client(overrides: object = {}): PublicClient {
	return {
		getChainId: async () => 84532,
		getCode: async () => undefined,
		getBalance: async () => 0n,
		...overrides,
	} as unknown as PublicClient;
}

test("role admin must be a valid nonzero address", () => {
	assert.throws(() => roleAdmin(zeroAddress));
	assert.throws(() => roleAdmin("invalid"));
});

test("wrong-chain RPC stops before inspecting addresses or balances", async () => {
	let reads = 0;
	const { checks } = await inspectDeployment(
		client({
			getChainId: async () => 1,
			getCode: async () => {
				reads++;
			},
		}),
		profile,
		"v1",
		admin,
		options,
	);
	assert.equal(checks.length, 1);
	assert.equal(checks[0].ok, false);
	assert.match(checks[0].message, /Wrong chain/);
	assert.equal(reads, 0);
});

test("missing dependencies and foreign bytecode are reported together", async () => {
	const { checks } = await inspectDeployment(
		client({
			getCode: async ({ address }: { address: Address }) =>
				address ===
				create3Address(CANONICAL_DEPLOYER, LABELS.walletImplementation)
					? "0x6000"
					: "0x",
		}),
		profile,
		"v1",
		admin,
		options,
	);
	assert.ok(checks.some((c) => !c.ok && /CreateX/.test(c.message)));
	assert.ok(checks.some((c) => !c.ok && /EntryPoint/.test(c.message)));
	assert.ok(checks.some((c) => !c.ok && /occupied by code/.test(c.message)));
});

test("RPC errors cannot disclose provider credentials", async () => {
	const { checks } = await inspectDeployment(
		client({
			getChainId: async () => {
				throw new Error("https://provider.invalid/SECRET_API_KEY");
			},
		}),
		profile,
		"v1",
		admin,
		options,
	);
	assert.equal(checks[0].ok, false);
	assert.doesNotMatch(JSON.stringify(checks), /SECRET_API_KEY/);
	assert.match(checks[0].message, /endpoint access/);
});

test("existing code of another release than the selected one blocks adoption", async () => {
	const wallet = create3Address(
		CANONICAL_DEPLOYER,
		LABELS.walletImplementation,
	);
	const { checks } = await inspectDeployment(
		client({
			getCode: async ({ address }: { address: Address }) =>
				address === wallet ? devnetCode(wallet) : "0x",
		}),
		profile,
		"v1",
		admin,
		options,
	);
	assert.ok(
		checks.some(
			(c) =>
				!c.ok &&
				/already holds release v2, not the selected v1/.test(c.message),
		),
	);
});

const planFor = (chain: PublicClient) =>
	planCore(chain, {
		network: "testnet",
		signer: null,
		deployer: CANONICAL_DEPLOYER,
	});

test("absent contracts require no storage reads, including providers returning 0x", async () => {
	const chain = client({ getCode: async () => "0x" });
	await verifyCoreState(chain, admin, profile, await planFor(chain));
});

test("existing proxy storage must point to the planned implementation", async () => {
	const proxy = create3Address(CANONICAL_DEPLOYER, LABELS.paymasterProxy);
	const chain = client({
		getCode: async ({ address }: { address: Address }) =>
			address === proxy ? "0x6000" : undefined,
		getStorageAt: async () => `0x${"0".repeat(64)}`,
	});
	await assert.rejects(
		verifyCoreState(chain, admin, profile, await planFor(chain)),
		/unexpected implementation/,
	);
});

test("an existing paymaster with the wrong role admin is rejected", async () => {
	const proxy = create3Address(CANONICAL_DEPLOYER, LABELS.paymasterProxy);
	const implementation = create3Address(
		CANONICAL_DEPLOYER,
		LABELS.paymasterImplementation,
	);
	const chain = client({
		getCode: async ({ address }: { address: Address }) =>
			address === proxy ? "0x6000" : undefined,
		getStorageAt: async () => `0x${"0".repeat(24)}${implementation.slice(2)}`,
		readContract: async ({ functionName }: { functionName: string }) =>
			functionName === "hasRole" ? false : 0n,
	});
	await assert.rejects(
		verifyCoreState(chain, admin, profile, await planFor(chain)),
	);
});

/** Runs `guided.ts --plan` against a stub RPC that answers every read with "nothing here". */
async function guidedPlan(chainId: number, selection: string[]) {
	const methods: string[] = [];
	const server = createServer(async (req, res) => {
		let body = "";
		for await (const chunk of req) body += chunk;
		const request = JSON.parse(body);
		methods.push(request.method);
		res.setHeader("Content-Type", "application/json");
		res.end(
			JSON.stringify({
				jsonrpc: "2.0",
				id: request.id,
				result:
					request.method === "eth_chainId"
						? `0x${chainId.toString(16)}`
						: request.method === "eth_getBalance"
							? "0x0"
							: "0x",
			}),
		);
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const address = server.address();
	assert.ok(address && typeof address !== "string");
	try {
		const result = await promisify(execFile)(
			process.execPath,
			[
				"--import",
				"tsx",
				"deploy/guided.ts",
				"--plan",
				...selection,
				"--rpc",
				`http://127.0.0.1:${address.port}`,
				"--role-admin",
				admin,
			],
			{
				cwd: new URL("..", import.meta.url),
				env: { ...process.env, CANONICAL_DEPLOYER_PRIVATE_KEY: "" },
			},
		).then(
			({ stdout }) => ({ code: 0, stdout }),
			(error: { code: number; stdout: string }) => ({
				code: error.code,
				stdout: error.stdout,
			}),
		);
		return { ...result, methods };
	} finally {
		await new Promise<void>((resolve) => server.close(() => resolve()));
	}
}

const READ_METHODS = ["eth_chainId", "eth_getCode", "eth_getBalance"];

test("CLI --plan is read-only and blocks a testnet while its canonical deployer is unset", async () => {
	for (const [chainId, chain] of [
		[84532, "base-sepolia"],
		[11155111, "ethereum-sepolia"],
	] as const) {
		const { code, stdout, methods } = await guidedPlan(chainId, [
			"--chain",
			chain,
		]);
		assert.equal(code, 1);
		if (DEPLOYERS.testnet === null)
			assert.match(stdout, /testnet canonical deployer is not configured/);
		assert.doesNotMatch(
			stdout,
			/Fund 0x000000000000000000000000000000000000dEaD/,
		);
		assert.ok(methods.length > 1);
		assert.ok(
			methods.every((method) => READ_METHODS.includes(method)),
			methods.join(", "),
		);
	}
});

test("a mainnet profile while the mainnet deployer is unset: prints the plan, sends nothing, exits non-zero", async () => {
	if (DEPLOYERS.mainnet !== null) return;
	const dir = mkdtempSync(join(tmpdir(), "giano-mainnet-profile-"));
	try {
		const file = join(dir, "mainnet.json");
		writeFileSync(
			file,
			JSON.stringify({
				...profile,
				chainId: 8453,
				network: "mainnet",
				name: "Base",
				rpcUrlEnv: "BASE_RPC_URL",
			}),
		);
		const { code, stdout, methods } = await guidedPlan(8453, [
			"--config",
			file,
		]);
		assert.equal(code, 1);
		assert.match(stdout, /Deployment plan \(mainnet\)/);
		assert.match(stdout, /walletImplementation .* expected \(none\)/);
		assert.match(
			stdout,
			/BLOCKED: The mainnet canonical deployer is not configured/,
		);
		assert.ok(
			methods.every((method) => READ_METHODS.includes(method)),
			methods.join(", "),
		);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});
