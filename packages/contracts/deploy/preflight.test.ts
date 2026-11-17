import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";
import {
	type Address,
	getAddress,
	type Hex,
	type PublicClient,
	zeroAddress,
} from "viem";
import { DEPLOYERS, LABELS } from "./config";
import { create3Address } from "./create3";
import { planCore } from "./plan";
import {
	assertRoleAdminNotDeployer,
	handOffScanStart,
	inspectDeployment,
	profileCoreConfig,
	roleAdmin,
	scanStartProblem,
	timelockMismatch,
	verifyCoreState,
} from "./preflight";
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
		// A bare chain: no Cancun. Only an EVM refusal reads as that (G42 R2).
		call: async () => {
			throw new Error("invalid opcode: opcode 0x5c not defined");
		},
		...overrides,
	} as unknown as PublicClient;
}

test("role admin must be a valid nonzero address", () => {
	assert.throws(() => roleAdmin(zeroAddress));
	assert.throws(() => roleAdmin("invalid"));
});

test("a deployer key is refused as role admin on a non-local chain", () => {
	const signer = "0x2222222222222222222222222222222222222222" as Address;
	assert.throws(
		() => assertRoleAdminNotDeployer(signer, signer, false),
		/must be a timelock or Safe, never a deployer/,
	);
	assert.doesNotThrow(() => assertRoleAdminNotDeployer(admin, signer, false));
	// Local chains (anvil) use a dev key for both.
	assert.doesNotThrow(() => assertRoleAdminNotDeployer(signer, signer, true));
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
				/already holds release v3, not the selected v1/.test(c.message),
		),
	);
});

test("a plan without a key checks the canonical deployer's balance, naming the address to fund", async () => {
	const { checks } = await inspectDeployment(
		client(),
		profile,
		"v2",
		admin,
		options,
	);
	assert.ok(
		checks.some(
			(c) =>
				!c.ok &&
				c.message.includes(`Fund ${CANONICAL_DEPLOYER} on ${profile.name}`),
		),
		JSON.stringify(checks),
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
	await verifyCoreState(
		chain,
		admin,
		profileCoreConfig(profile),
		await planFor(chain),
	);
});

test("existing proxy storage must point to the planned implementation", async () => {
	const proxy = create3Address(CANONICAL_DEPLOYER, LABELS.paymasterProxy);
	const chain = client({
		getCode: async ({ address }: { address: Address }) =>
			address === proxy ? "0x6000" : undefined,
		getStorageAt: async () => `0x${"0".repeat(64)}`,
	});
	await assert.rejects(
		verifyCoreState(
			chain,
			admin,
			profileCoreConfig(profile),
			await planFor(chain),
		),
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
		verifyCoreState(
			chain,
			admin,
			profileCoreConfig(profile),
			await planFor(chain),
		),
	);
});

test("an existing paymaster is checked against the run's configuration, and no deployer may hold ROLE_ADMIN", async () => {
	const proxy = create3Address(CANONICAL_DEPLOYER, LABELS.paymasterProxy);
	const implementation = create3Address(
		CANONICAL_DEPLOYER,
		LABELS.paymasterImplementation,
	);
	const config = profileCoreConfig(profile);
	const chain = (holders: Address[]) =>
		client({
			getCode: async ({ address }: { address: Address }) =>
				address === proxy ? "0x6000" : undefined,
			getStorageAt: async () => `0x${"0".repeat(24)}${implementation.slice(2)}`,
			readContract: async ({
				functionName,
				args,
			}: {
				functionName: string;
				args?: [unknown, Address];
			}) =>
				({
					ROLE_ADMIN: `0x${"0".repeat(64)}`,
					hasRole: holders.includes(args?.[1] as Address),
					entryPoint: config.entryPoint,
					defaultFeeWei: config.defaultFeeWei,
					postOpGasAllowance: config.postOpGasAllowance,
					penaltyBps: config.penaltyBps,
				})[functionName],
		});
	const ok = chain([admin]);
	assert.deepEqual(
		await verifyCoreState(ok, admin, config, await planFor(ok)),
		[],
	);
	// Fees are tuned by the fee and parameter admins after deployment: a fee that differs from the
	// run's configuration is a warning, not a refusal (the verify-only Helm Job must still pass).
	const warnings = await verifyCoreState(
		ok,
		admin,
		{ ...config, penaltyBps: config.penaltyBps + 1 },
		await planFor(ok),
	);
	assert.equal(warnings.length, 1);
	assert.match(warnings[0], /penaltyBps is \d+ on chain/);
	// The EntryPoint is not tunable: a different one is refused.
	await assert.rejects(
		verifyCoreState(
			ok,
			admin,
			{ ...config, entryPoint: CANONICAL_DEPLOYER },
			await planFor(ok),
		),
		/EntryPoint differs/,
	);
	const held = chain([admin, CANONICAL_DEPLOYER]);
	await assert.rejects(
		verifyCoreState(held, admin, config, await planFor(held)),
		/A deployer must hold no role/,
	);
	// After the hand-off the timelock holds ROLE_ADMIN and the bootstrap key does not (N2): the chain
	// verifies once the profile names its timelock, and is refused while it does not.
	const timelock = getAddress("0x00000000000000000000000000000000000071e1");
	const handedOff = chain([timelock]);
	await assert.rejects(
		verifyCoreState(handedOff, admin, config, await planFor(handedOff)),
		/does not hold ROLE_ADMIN.*set the profile's timelock.address/,
	);
	assert.deepEqual(
		await verifyCoreState(handedOff, admin, config, await planFor(handedOff), {
			timelock,
		}),
		[],
	);
	const nobody = chain([]);
	await assert.rejects(
		verifyCoreState(nobody, admin, config, await planFor(nobody), {
			timelock,
		}),
		/Neither the profile's ROLE_ADMIN .* nor its timelock/,
	);
});

/**
 * Runs `guided.ts --plan` (or `command`, e.g. `deploy/cli.ts core`) against a stub RPC that answers
 * every read with "nothing here".
 */
async function guidedPlan(
	chainId: number,
	selection: string[],
	command: string[] = ["deploy/guided.ts", "--plan"],
) {
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
				...command,
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
			({ stdout, stderr }) => ({ code: 0, stdout, stderr }),
			(error: { code: number; stdout: string; stderr: string }) => ({
				code: error.code,
				stdout: error.stdout,
				stderr: error.stderr,
			}),
		);
		return { ...result, methods };
	} finally {
		await new Promise<void>((resolve) => server.close(() => resolve()));
	}
}

/** eth_call simulates without sending: the chain prerequisites probe Cancun's opcodes with one. */
const READ_METHODS = [
	"eth_chainId",
	"eth_getCode",
	"eth_getBalance",
	"eth_call",
];

test("deploy:cli --network cannot move a chain out of its committed profile's class", async () => {
	const { code, stdout, stderr } = await guidedPlan(
		84532,
		["--network", "mainnet"],
		["deploy/cli.ts", "core"],
	);
	assert.notEqual(code, 0);
	assert.match(
		`${stdout}${stderr}`,
		/--network mainnet conflicts with profile base-sepolia, which declares chain 84532 testnet/,
	);
});

test("deploy:cli refuses a deployment record that states another network class", async () => {
	const dir = mkdtempSync(join(tmpdir(), "giano-record-class-"));
	try {
		// Chain 4242 has no committed profile, so --network alone picks its class.
		writeFileSync(
			join(dir, "4242.json"),
			JSON.stringify({
				chainId: 4242,
				network: "mainnet",
				deployer: zeroAddress,
				contracts: {},
				upgrades: [],
			}),
		);
		const { code, stdout, stderr, methods } = await guidedPlan(
			4242,
			["--network", "testnet", "--record-dir", dir],
			["deploy/cli.ts", "core"],
		);
		assert.notEqual(code, 0);
		assert.match(
			`${stdout}${stderr}`,
			/states chain 4242 is mainnet, but this run resolved it as testnet \(--network\)/,
		);
		assert.deepEqual(methods, ["eth_chainId"]);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

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

test("a hand-off goes only to the published timelock: the profile's, else the record's", () => {
	const published = getAddress("0x00000000000000000000000000000000000071e1");
	const other = getAddress("0x00000000000000000000000000000000000071e2");
	assert.equal(timelockMismatch(published, { profile: published }), undefined);
	assert.equal(
		timelockMismatch(published, { profile: published.toLowerCase() }),
		undefined,
	);
	assert.match(
		timelockMismatch(other, { profile: published }) ?? "",
		/--timelock 0x0+71e2 is not the published timelock 0x0+71e1 \(the chain profile\)/i,
	);
	// The profile wins over a record that names another timelock.
	assert.match(
		timelockMismatch(other, { profile: published, record: other }) ?? "",
		/the chain profile/,
	);
	assert.match(
		timelockMismatch(other, { record: published }) ?? "",
		/\(the deployment record\)/,
	);
	// Nothing published: refused, not waved through (G42 R4).
	assert.match(
		timelockMismatch(other, {}) ?? "",
		/no published timelock address to check --timelock 0x0+71e2 against/i,
	);
});

test("a --from-block start needs the timelock to have had no code before it (G42 R5, #298 review)", async () => {
	const timelock = getAddress("0x00000000000000000000000000000000000071e1");
	const deployedAt = 100n;
	const chain = {
		getCode: async ({ blockNumber }: { blockNumber?: bigint }) =>
			blockNumber !== undefined && blockNumber >= deployedAt ? "0x6001" : "0x",
	} as unknown as PublicClient;
	assert.equal(await scanStartProblem(chain, timelock, 0n), undefined);
	assert.equal(await scanStartProblem(chain, timelock, 90n), undefined);
	assert.equal(await scanStartProblem(chain, timelock, deployedAt), undefined);
	assert.match(
		(await scanStartProblem(chain, timelock, deployedAt + 1n)) ?? "",
		/--from-block 101 is after the timelock's deployment: .* already has code at block 100/,
	);
	// An RPC without historical state cannot vouch for the start: refused.
	const pruned = {
		getCode: async () => {
			throw new Error("missing trie node");
		},
	} as unknown as PublicClient;
	assert.match(
		(await scanStartProblem(pruned, timelock, 50n)) ?? "",
		/needs an RPC that serves historical state/,
	);
});

test("the hand-off scan starts at the recorded deployment; --from-block never starts later (G42 R5)", () => {
	// No --from-block: the recorded deployment's block, or nothing (the scan then fails closed).
	assert.equal(
		handOffScanStart({ recordedTransaction: true, deployedAt: 100n }),
		100n,
	);
	assert.equal(handOffScanStart({ recordedTransaction: false }), undefined);
	// No recorded deployment transaction: --from-block stands in for it.
	assert.equal(
		handOffScanStart({ recordedTransaction: false, fromBlock: "42" }),
		42n,
	);
	// A recorded deployment: an earlier start scans more and is fine; a later one is refused.
	assert.equal(
		handOffScanStart({
			recordedTransaction: true,
			deployedAt: 100n,
			fromBlock: "90",
		}),
		90n,
	);
	assert.throws(
		() =>
			handOffScanStart({
				recordedTransaction: true,
				deployedAt: 100n,
				fromBlock: "101",
			}),
		/--from-block 101 is later than the timelock's deployment block 100/,
	);
	// A recorded transaction whose receipt could not be read is not replaced by --from-block.
	assert.throws(
		() => handOffScanStart({ recordedTransaction: true, fromBlock: "1" }),
		/receipt could not be read/,
	);
	assert.throws(
		() => handOffScanStart({ recordedTransaction: false, fromBlock: "0x10" }),
		/not a block number/,
	);
});
