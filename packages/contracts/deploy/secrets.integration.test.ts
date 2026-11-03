/**
 * The deploy tooling never prints a deployer key or writes it anywhere (openspec:
 * production-key-ceremony, "Deploy tooling never persists a deployer key"). Runs `deploy:cli core`
 * with a key on a throwaway local anvil, and the guided wizard's plan with a key set, then searches
 * their output and every file they wrote for the key, with and without its 0x prefix.
 */
import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";

const exec = promisify(execFile);
/** Anvil's second default key: funded on anvil, worthless anywhere else. */
const KEY =
	"0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const cwd = new URL("..", import.meta.url);

/** Fails if `text` contains the key in any spelling. */
function assertNoKey(text: string, where: string): void {
	const haystack = text.toLowerCase();
	assert.ok(!haystack.includes(KEY.slice(2)), `${where} contains the key`);
}

async function run(args: string[], env: Record<string, string>) {
	return exec(process.execPath, ["--import", "tsx", ...args], {
		cwd,
		env: { ...process.env, ...env },
	}).then(
		({ stdout, stderr }) => ({ code: 0, stdout, stderr }),
		(error: { code: number; stdout: string; stderr: string }) => ({
			code: error.code,
			stdout: error.stdout,
			stderr: error.stderr,
		}),
	);
}

/** The address of {@link KEY}. */
const SIGNER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
/** A role admin that is not the signer (the wizard refuses a deployer as ROLE_ADMIN). */
const ROLE_ADMIN = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";

/** Starts anvil on a free port with `chainId`; resolves once it answers. */
async function startAnvil(chainId: number) {
	const socket = createServer();
	await new Promise<void>((resolve) => socket.listen(0, "127.0.0.1", resolve));
	const port = (socket.address() as { port: number }).port;
	await new Promise<void>((resolve) => socket.close(() => resolve()));
	const process = spawn(
		"anvil",
		[
			"--host",
			"127.0.0.1",
			"--port",
			String(port),
			"--chain-id",
			String(chainId),
			"--silent",
		],
		{ stdio: "ignore" },
	);
	const rpc = `http://127.0.0.1:${port}`;
	for (let i = 0; ; i++) {
		try {
			await fetch(rpc, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}',
			});
			break;
		} catch (error) {
			if (i >= 50) throw error;
			await delay(100);
		}
	}
	return { rpc, process };
}

test("deploy:cli and the guided wizard never print or record the deployer key", {
	timeout: 120000,
}, async () => {
	const local = await startAnvil(31337);
	// The guided wizard's profile (base-sepolia) is chain 84532: a matching chain, so it gets past
	// the chain check and prints its plan.
	const sepolia = await startAnvil(84532);
	const dir = mkdtempSync(join(tmpdir(), "giano-secrets-"));
	try {
		const rpc = local.rpc;
		for (let i = 0; ; i++) {
			const probe = await run(["deploy/cli.ts", "addresses"], {});
			if (probe.code === 0) break;
			if (i > 20) throw new Error("cli does not start");
		}
		const outputs: string[] = [];
		for (const command of ["install-createx", "install-entrypoint"]) {
			const result = await run(["deploy/cli.ts", command, "--rpc", rpc], {});
			assert.equal(result.code, 0, result.stderr);
		}
		const core = await run(
			[
				"deploy/cli.ts",
				"core",
				"--rpc",
				rpc,
				"--role-admin",
				SIGNER,
				"--record-dir",
				dir,
			],
			{ DEPLOYER_PRIVATE_KEY: KEY },
		);
		assert.equal(core.code, 0, core.stderr);
		assert.match(core.stdout, /\+ giano\.paymaster\.proxy/);
		outputs.push(core.stdout, core.stderr);

		// The guided wizard's plan, with the key in its variable. It loads the key (the plan names its
		// signer) and prints the plan, then exits non-zero: a fresh anvil has no CreateX or EntryPoint,
		// and the testnet deployer may be unset. Neither stops the plan from being printed.
		const guided = await run(
			[
				"deploy/guided.ts",
				"--plan",
				"--chain",
				"base-sepolia",
				"--rpc",
				sepolia.rpc,
				"--role-admin",
				ROLE_ADMIN,
			],
			{ CANONICAL_DEPLOYER_PRIVATE_KEY: KEY },
		);
		assert.equal(guided.code, 1, guided.stderr);
		assert.match(guided.stdout, /OK: RPC is .* \(84532\)/);
		assert.match(guided.stdout, /OK: Deployment plan \(testnet\)/);
		assert.match(
			guided.stdout,
			new RegExp(
				`Network class: testnet; canonical deployer: .*; signer: ${SIGNER}`,
			),
		);
		assert.match(guided.stdout, /walletImplementation\s+expected/);
		outputs.push(guided.stdout, guided.stderr);

		// A malformed key must not be echoed back in an error either.
		for (const bad of [`${KEY}00`, KEY.slice(0, 40)]) {
			const result = await run(
				[
					"deploy/cli.ts",
					"core",
					"--rpc",
					rpc,
					"--role-admin",
					"0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
					"--record-dir",
					dir,
				],
				{ DEPLOYER_PRIVATE_KEY: bad },
			);
			assert.notEqual(result.code, 0);
			assert.ok(
				!`${result.stdout}${result.stderr}`
					.toLowerCase()
					.includes(bad.slice(2, 40)),
				"an error echoed a malformed key",
			);
		}

		for (const [i, text] of outputs.entries()) assertNoKey(text, `output ${i}`);
		const files = readdirSync(dir);
		assert.ok(files.includes("31337.json"));
		for (const file of files)
			assertNoKey(readFileSync(join(dir, file), "utf8"), file);
	} finally {
		local.process.kill();
		sepolia.process.kill();
		rmSync(dir, { recursive: true, force: true });
	}
});
