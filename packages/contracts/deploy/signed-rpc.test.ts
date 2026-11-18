import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type IncomingHttpHeaders } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";
import { createPublicClient, type Hex, recoverMessageAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { signatureHeaders, signedHttp } from "./signed-rpc";

/** The stub RPC's chain id by default: a local chain, where provisioning falls back to the anvil key. */
const CHAIN_ID = 31337;
/** A chain id that is not local, so provisioning has no fallback key. */
const REMOTE_CHAIN_ID = 54321;
/** Anvil's first account: a well-known test key, never a real one. */
const ROOT_KEY =
	"0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ROLE_ADMIN_KEY =
	"0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const root = privateKeyToAccount(ROOT_KEY);
const roleAdmin = privateKeyToAccount(ROLE_ADMIN_KEY);

/** RFC 3339 date-time: `2026-11-16T09:30:00.123Z` or with a numeric offset. */
const RFC_3339 =
	/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

type Received = {
	method: string;
	body: string;
	headers: IncomingHttpHeaders;
	chainId: number;
};

/**
 * A stub RPC that records every request (its exact body and headers) and answers every read with
 * "nothing here", so a deploy:cli run stops at its first check.
 */
async function withStubRpc<T>(
	run: (url: string, received: Received[]) => Promise<T>,
	chainId = CHAIN_ID,
): Promise<T> {
	const received: Received[] = [];
	const server = createServer(async (req, res) => {
		let body = "";
		for await (const chunk of req) body += chunk;
		const request = JSON.parse(body);
		received.push({
			method: request.method,
			body,
			headers: req.headers,
			chainId,
		});
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
		return await run(`http://127.0.0.1:${address.port}`, received);
	} finally {
		await new Promise<void>((resolve) => server.close(() => resolve()));
	}
}

/** The address that signed `chainId + body + timestamp` for this request. */
function payloadSigner({ body, headers, chainId }: Received) {
	return recoverMessageAddress({
		message: `${chainId}${body}${headers["x-timestamp"]}`,
		signature: headers["x-signature"] as Hex,
	});
}

test("signedHttp signs chainId + exact body + timestamp with the key", async () => {
	await withStubRpc(async (url, received) => {
		const client = createPublicClient({
			transport: signedHttp(url, { chainId: CHAIN_ID, signer: root }),
		});
		const before = Date.now();
		await client.getChainId();
		await client.getBalance({ address: root.address });

		assert.equal(received.length, 2);
		for (const request of received) {
			const timestamp = String(request.headers["x-timestamp"]);
			assert.match(timestamp, RFC_3339);
			const signedAt = Date.parse(timestamp);
			assert.ok(signedAt >= before - 1000 && signedAt <= Date.now() + 1000);
			assert.equal(await payloadSigner(request), root.address);
		}
	});
});

test("a body that is not a string is refused, never signed over other bytes", async () => {
	const sign = (message: string) => root.signMessage({ message });
	for (const body of [null, undefined, new Uint8Array([1]), new Blob(["{}"])])
		await assert.rejects(
			signatureHeaders(CHAIN_ID, body, sign),
			/cannot sign an RPC request whose body is not a string/,
		);
	const headers = await signatureHeaders(CHAIN_ID, "{}", sign);
	assert.equal(
		await recoverMessageAddress({
			message: `${CHAIN_ID}{}${headers["x-timestamp"]}`,
			signature: headers["x-signature"] as Hex,
		}),
		root.address,
	);
});

/** Runs `deploy:cli core` against the stub RPC with the given extra flags and key. */
function deployCore(url: string, flags: string[], key: string) {
	return runScript(
		[
			"deploy/cli.ts",
			"core",
			"--rpc",
			url,
			"--role-admin",
			"0x00000000000000000000000000000000000000aa",
			...flags,
		],
		key,
	);
}

/**
 * Runs a package script with tsx, with DEPLOYER_PRIVATE_KEY set to `key` ("" for none) and only
 * the variables `env` sets besides PATH and HOME: nothing from the shell running the tests (a
 * leftover GIANO_REHEARSAL_DEPLOYER, RPC_URL or key) can change the result.
 */
function runScript(args: string[], key: string, env: NodeJS.ProcessEnv = {}) {
	return promisify(execFile)(process.execPath, ["--import", "tsx", ...args], {
		cwd: new URL("..", import.meta.url),
		env: {
			PATH: process.env.PATH,
			HOME: process.env.HOME,
			...env,
			DEPLOYER_PRIVATE_KEY: key,
		},
	}).then(
		({ stdout, stderr }) => ({ code: 0, stdout, stderr }),
		(error: { code: number; stdout: string; stderr: string }) => ({
			code: error.code,
			stdout: error.stdout,
			stderr: error.stderr,
		}),
	);
}

test("deploy:cli core --signed-rpc without DEPLOYER_PRIVATE_KEY exits non-zero and sends no request", async () => {
	await withStubRpc(async (url, received) => {
		const { code, stdout, stderr } = await deployCore(
			url,
			["--signed-rpc"],
			"",
		);
		assert.notEqual(code, 0);
		assert.match(
			`${stdout}${stderr}`,
			/--signed-rpc needs DEPLOYER_PRIVATE_KEY/,
		);
		assert.deepEqual(received, []);
	});
});

test("provision:paymaster --signed-rpc without DEPLOYER_PRIVATE_KEY exits non-zero after the chain id read", async () => {
	await withStubRpc(async (url, received) => {
		const { code, stdout, stderr } = await provision(url, ["--signed-rpc"], "");
		assert.notEqual(code, 0);
		assert.match(
			`${stdout}${stderr}`,
			/--signed-rpc needs DEPLOYER_PRIVATE_KEY/,
		);
		assert.ok(received.length > 0);
		assert.ok(received.every(({ method }) => method === "eth_chainId"));
	}, REMOTE_CHAIN_ID);
});

test("provision:paymaster --signed-rpc on a local chain without DEPLOYER_PRIVATE_KEY signs with the anvil key", async () => {
	await withStubRpc(async (url, received) => {
		await provision(url, ["--signed-rpc"], "");
		const signed = received.filter(({ method }) => method !== "eth_chainId");
		assert.ok(signed.length > 0);
		// ROOT_KEY is anvil's first account, the key the unsigned run falls back to.
		for (const request of signed)
			assert.equal(await payloadSigner(request), root.address, request.method);
	});
});

/** Runs `provision:paymaster` against the stub RPC with an explicit paymaster and DEPLOYER_PRIVATE_KEY. */
function provision(url: string, flags: string[], key = ROOT_KEY) {
	return runScript(
		[
			"scripts/provision-paymaster.ts",
			"--rpc",
			url,
			"--paymaster",
			"0x00000000000000000000000000000000000000dd",
			...flags,
		],
		key,
	);
}

test("provision:paymaster --signed-rpc signs every request after the chain id read with DEPLOYER_PRIVATE_KEY", async () => {
	await withStubRpc(async (url, received) => {
		await provision(url, ["--signed-rpc"]);
		// ethers may read the chain id more than once before it switches to the signed provider.
		const signed = received.filter(({ method }) => method !== "eth_chainId");
		assert.ok(signed.length > 0);
		for (const request of signed) {
			assert.match(String(request.headers["x-timestamp"]), RFC_3339);
			assert.equal(await payloadSigner(request), root.address, request.method);
		}
	});
});

test("provision:paymaster without --signed-rpc sends no signature headers", async () => {
	await withStubRpc(async (url, received) => {
		await provision(url, []);
		assert.ok(received.some(({ method }) => method !== "eth_chainId"));
		for (const { headers, method } of received) {
			assert.equal(headers["x-timestamp"], undefined, method);
			assert.equal(headers["x-signature"], undefined, method);
		}
	});
});

test("deploy:cli core --signed-rpc signs every request after the chain id read with DEPLOYER_PRIVATE_KEY", async () => {
	await withStubRpc(async (url, received) => {
		await deployCore(url, ["--signed-rpc"], ROOT_KEY);
		// The signature covers the chain id, so the first eth_chainId goes unsigned.
		const [first, ...rest] = received;
		assert.equal(first.method, "eth_chainId");
		assert.ok(rest.length > 0);
		for (const request of rest)
			assert.equal(await payloadSigner(request), root.address, request.method);
	});
});

test("deploy:cli core without --signed-rpc sends no signature headers", async () => {
	await withStubRpc(async (url, received) => {
		await deployCore(url, [], ROOT_KEY);
		assert.ok(received.length > 1);
		for (const { headers, method } of received) {
			assert.equal(headers["x-timestamp"], undefined, method);
			assert.equal(headers["x-signature"], undefined, method);
		}
	});
});

/** Runs `deploy:cli <command>` against the stub RPC with ROLE_ADMIN_PRIVATE_KEY set to `roleAdminKey`. */
function deployRoleAdmin(
	url: string,
	command: "timelock" | "handoff",
	roleAdminKey: string,
) {
	const flags =
		command === "timelock"
			? ["--proposer", "0x00000000000000000000000000000000000000bb"]
			: [
					"--timelock",
					"0x00000000000000000000000000000000000000cc",
					"--execute",
				];
	return runScript(
		["deploy/cli.ts", command, "--rpc", url, ...flags, "--signed-rpc"],
		ROOT_KEY,
		{ ROLE_ADMIN_PRIVATE_KEY: roleAdminKey },
	);
}

for (const command of ["timelock", "handoff"] as const) {
	test(`deploy:cli ${command} --signed-rpc without ROLE_ADMIN_PRIVATE_KEY exits non-zero and sends no request`, async () => {
		await withStubRpc(async (url, received) => {
			const { code, stdout, stderr } = await deployRoleAdmin(url, command, "");
			assert.notEqual(code, 0);
			assert.match(
				`${stdout}${stderr}`,
				/--signed-rpc needs ROLE_ADMIN_PRIVATE_KEY/,
			);
			assert.deepEqual(received, []);
		});
	});

	test(`deploy:cli ${command} --signed-rpc signs every request after the chain id read with ROLE_ADMIN_PRIVATE_KEY`, async () => {
		await withStubRpc(async (url, received) => {
			// DEPLOYER_PRIVATE_KEY is set too: the role admin, not the deployer, must sign.
			await deployRoleAdmin(url, command, ROLE_ADMIN_KEY);
			const [first, ...rest] = received;
			assert.equal(first.method, "eth_chainId");
			assert.ok(rest.length > 0);
			for (const request of rest)
				assert.equal(
					await payloadSigner(request),
					roleAdmin.address,
					request.method,
				);
		});
	});
}

test("deploy:cli upgrade --execute --signed-rpc without UPGRADER_PRIVATE_KEY exits non-zero and sends no request", async () => {
	await withStubRpc(async (url, received) => {
		const { code, stdout, stderr } = await runScript(
			[
				"deploy/cli.ts",
				"upgrade",
				"--rpc",
				url,
				"--contract",
				"paymaster",
				"--execute",
				"--signed-rpc",
			],
			ROOT_KEY,
		);
		assert.notEqual(code, 0);
		assert.match(
			`${stdout}${stderr}`,
			/--signed-rpc needs UPGRADER_PRIVATE_KEY/,
		);
		assert.deepEqual(received, []);
	});
});

test("deploy:cli upgrade --execute without UPGRADER_PRIVATE_KEY and without --signed-rpc exits non-zero and sends no request", async () => {
	await withStubRpc(async (url, received) => {
		const { code, stdout, stderr } = await runScript(
			[
				"deploy/cli.ts",
				"upgrade",
				"--rpc",
				url,
				"--contract",
				"paymaster",
				"--execute",
			],
			ROOT_KEY,
		);
		assert.notEqual(code, 0);
		assert.match(`${stdout}${stderr}`, /--execute needs UPGRADER_PRIVATE_KEY/);
		assert.deepEqual(received, []);
	});
});

test("deploy:cli upgrade --execute with a malformed UPGRADER_PRIVATE_KEY and without --signed-rpc exits non-zero and sends no request", async () => {
	await withStubRpc(async (url, received) => {
		const { code, stdout, stderr } = await runScript(
			[
				"deploy/cli.ts",
				"upgrade",
				"--rpc",
				url,
				"--contract",
				"paymaster",
				"--execute",
			],
			ROOT_KEY,
			{ UPGRADER_PRIVATE_KEY: "0x1234" },
		);
		assert.notEqual(code, 0);
		assert.match(
			`${stdout}${stderr}`,
			/UPGRADER_PRIVATE_KEY is not a valid private key/,
		);
		assert.deepEqual(received, []);
	});
});

test("deploy:cli handoff --signed-rpc without --execute plans unsigned and needs no ROLE_ADMIN_PRIVATE_KEY", async () => {
	await withStubRpc(async (url, received) => {
		const { stdout, stderr } = await runScript(
			[
				"deploy/cli.ts",
				"handoff",
				"--rpc",
				url,
				"--timelock",
				"0x00000000000000000000000000000000000000cc",
				"--signed-rpc",
			],
			ROOT_KEY,
		);
		const output = `${stdout}${stderr}`;
		assert.doesNotMatch(output, /needs ROLE_ADMIN_PRIVATE_KEY/);
		assert.match(output, /the plan only reads, so its requests go unsigned/);
		assert.ok(received.length > 1);
		for (const { headers, method } of received)
			assert.equal(headers["x-signature"], undefined, method);
	});
});

/**
 * Runs the wizard (`contracts:deploy`) against the stub RPC, for a testnet profile of its chain. Without a
 * terminal it stops after the read-only plan, so it sends no transaction. `flags` may add --plan.
 */
async function wizard(url: string, flags: string[], canonicalKey: string) {
	const dir = mkdtempSync(join(tmpdir(), "giano-signed-wizard-"));
	try {
		const profile = join(dir, "custom.json");
		writeFileSync(
			profile,
			JSON.stringify({
				chainId: REMOTE_CHAIN_ID,
				network: "testnet",
				name: "Custom test chain",
				rpcUrl: url,
				rpcUrlEnv: "CUSTOM_TEST_RPC_URL",
				release: "v3",
				roleAdmin: "0x00000000000000000000000000000000000000aa",
				minDeployerBalanceEth: "0.05",
				paymaster: {
					defaultFeeWei: "0",
					postOpGasAllowance: 40000,
					penaltyBps: 1000,
				},
			}),
		);
		return await runScript(
			["deploy/guided.ts", "--config", profile, ...flags],
			"",
			{ CANONICAL_DEPLOYER_PRIVATE_KEY: canonicalKey },
		);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
}

test("contracts:deploy --signed-rpc without CANONICAL_DEPLOYER_PRIVATE_KEY exits non-zero and sends no request", async () => {
	await withStubRpc(async (url, received) => {
		const { code, stdout, stderr } = await wizard(url, ["--signed-rpc"], "");
		assert.notEqual(code, 0);
		assert.match(
			`${stdout}${stderr}`,
			/--signed-rpc needs CANONICAL_DEPLOYER_PRIVATE_KEY/,
		);
		assert.deepEqual(received, []);
	}, REMOTE_CHAIN_ID);
});

test("contracts:deploy --signed-rpc signs every request with CANONICAL_DEPLOYER_PRIVATE_KEY", async () => {
	await withStubRpc(async (url, received) => {
		await wizard(url, ["--signed-rpc"], ROOT_KEY);
		assert.ok(received.length > 0);
		// The profile gives the chain id, so even the first request is signed.
		for (const request of received) {
			assert.match(String(request.headers["x-timestamp"]), RFC_3339);
			assert.equal(await payloadSigner(request), root.address, request.method);
		}
	}, REMOTE_CHAIN_ID);
});

test("contracts:deploy --plan --signed-rpc needs no CANONICAL_DEPLOYER_PRIVATE_KEY and sends no signature headers", async () => {
	await withStubRpc(async (url, received) => {
		const { stdout, stderr } = await wizard(
			url,
			["--plan", "--signed-rpc"],
			"",
		);
		const output = `${stdout}${stderr}`;
		assert.doesNotMatch(
			output,
			/--signed-rpc needs CANONICAL_DEPLOYER_PRIVATE_KEY/,
		);
		assert.match(output, /the plan only reads, so its requests go unsigned/);
		assert.ok(received.length > 0);
		for (const { headers, method } of received)
			assert.equal(headers["x-signature"], undefined, method);
	}, REMOTE_CHAIN_ID);
});

test("contracts:deploy without --signed-rpc sends no signature headers", async () => {
	await withStubRpc(async (url, received) => {
		await wizard(url, [], ROOT_KEY);
		assert.ok(received.length > 0);
		for (const { headers, method } of received)
			assert.equal(headers["x-signature"], undefined, method);
	}, REMOTE_CHAIN_ID);
});
