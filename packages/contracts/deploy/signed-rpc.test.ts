import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createServer, type IncomingHttpHeaders } from "node:http";
import { test } from "node:test";
import { promisify } from "node:util";
import { createPublicClient, type Hex, recoverMessageAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
	type DelegateTicket,
	delegateTicketMessage,
	signedHttp,
} from "./signed-rpc";

const CHAIN_ID = 31337;
/** Anvil's first account: a well-known test key, never a real one. */
const ROOT_KEY =
	"0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const EPHEMERAL_KEY =
	"0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const root = privateKeyToAccount(ROOT_KEY);
const ephemeral = privateKeyToAccount(EPHEMERAL_KEY);

/** RFC 3339 date-time: `2026-11-16T09:30:00.123Z` or with a numeric offset. */
const RFC_3339 =
	/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

type Received = { method: string; body: string; headers: IncomingHttpHeaders };

/**
 * A stub RPC that records every request (its exact body and headers) and answers every read with
 * "nothing here", so a deploy:cli run stops at its first check.
 */
async function withStubRpc<T>(
	run: (url: string, received: Received[]) => Promise<T>,
): Promise<T> {
	const received: Received[] = [];
	const server = createServer(async (req, res) => {
		let body = "";
		for await (const chunk of req) body += chunk;
		const request = JSON.parse(body);
		received.push({ method: request.method, body, headers: req.headers });
		res.setHeader("Content-Type", "application/json");
		res.end(
			JSON.stringify({
				jsonrpc: "2.0",
				id: request.id,
				result:
					request.method === "eth_chainId"
						? `0x${CHAIN_ID.toString(16)}`
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
function payloadSigner({ body, headers }: Received) {
	return recoverMessageAddress({
		message: `${CHAIN_ID}${body}${headers["x-timestamp"]}`,
		signature: headers["x-signature"] as Hex,
	});
}

test("signedHttp signs chainId + exact body + timestamp with the key, and sends no delegate headers", async () => {
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
			assert.equal(request.headers["x-delegate"], undefined);
			assert.equal(request.headers["x-delegate-signature"], undefined);
		}
	});
});

test("signedHttp with a delegate: the ephemeral key signs each request, the ticket and the root's approval go along", async () => {
	const ticket: DelegateTicket = {
		expires: new Date(Date.now() + 3_600_000).toISOString(),
		ephemeralAddress: ephemeral.address,
	};
	const approval = await root.signMessage({
		message: delegateTicketMessage(CHAIN_ID, ticket),
	});
	assert.equal(
		delegateTicketMessage(CHAIN_ID, ticket),
		`${CHAIN_ID}{"expires":"${ticket.expires}","ephemeralAddress":"${ephemeral.address}"}`,
	);

	await withStubRpc(async (url, received) => {
		const client = createPublicClient({
			transport: signedHttp(url, {
				chainId: CHAIN_ID,
				signer: ephemeral,
				delegate: { ticket, signature: approval },
			}),
		});
		await client.getChainId();

		const [request] = received;
		assert.match(String(request.headers["x-timestamp"]), RFC_3339);
		assert.equal(await payloadSigner(request), ephemeral.address);
		assert.equal(request.headers["x-delegate"], JSON.stringify(ticket));
		assert.equal(request.headers["x-delegate-signature"], approval);
		assert.equal(
			await recoverMessageAddress({
				message: delegateTicketMessage(
					CHAIN_ID,
					JSON.parse(String(request.headers["x-delegate"])),
				),
				signature: request.headers["x-delegate-signature"] as Hex,
			}),
			root.address,
		);
	});
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
 * Runs a package script with tsx, with DEPLOYER_PRIVATE_KEY set to `key` ("" for none) and the
 * other signing keys unset unless `env` sets them.
 */
function runScript(args: string[], key: string, env: NodeJS.ProcessEnv = {}) {
	return promisify(execFile)(process.execPath, ["--import", "tsx", ...args], {
		cwd: new URL("..", import.meta.url),
		env: {
			...process.env,
			ROLE_ADMIN_PRIVATE_KEY: "",
			UPGRADER_PRIVATE_KEY: "",
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

test("provision:paymaster --signed-rpc without DEPLOYER_PRIVATE_KEY exits non-zero and sends no request", async () => {
	await withStubRpc(async (url, received) => {
		const { code, stdout, stderr } = await runScript(
			["scripts/provision-paymaster.ts", "--rpc", url, "--signed-rpc"],
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

/** Runs `provision:paymaster` against the stub RPC with an explicit paymaster and DEPLOYER_PRIVATE_KEY. */
function provision(url: string, flags: string[]) {
	return runScript(
		[
			"scripts/provision-paymaster.ts",
			"--rpc",
			url,
			"--paymaster",
			"0x00000000000000000000000000000000000000dd",
			...flags,
		],
		ROOT_KEY,
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
			await deployRoleAdmin(url, command, EPHEMERAL_KEY);
			const [first, ...rest] = received;
			assert.equal(first.method, "eth_chainId");
			assert.ok(rest.length > 0);
			for (const request of rest)
				assert.equal(
					await payloadSigner(request),
					ephemeral.address,
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
