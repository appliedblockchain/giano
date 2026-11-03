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

test("deploy:cli and the guided wizard never print or record the deployer key", {
	timeout: 120000,
}, async () => {
	const socket = createServer();
	await new Promise<void>((resolve) => socket.listen(0, "127.0.0.1", resolve));
	const port = (socket.address() as { port: number }).port;
	await new Promise<void>((resolve) => socket.close(() => resolve()));
	const anvil = spawn(
		"anvil",
		[
			"--host",
			"127.0.0.1",
			"--port",
			String(port),
			"--chain-id",
			"31337",
			"--silent",
		],
		{ stdio: "ignore" },
	);
	const dir = mkdtempSync(join(tmpdir(), "giano-secrets-"));
	try {
		const rpc = `http://127.0.0.1:${port}`;
		for (let i = 0; ; i++) {
			const probe = await run(["deploy/cli.ts", "addresses"], {});
			if (probe.code === 0) break;
			if (i > 20) throw new Error("cli does not start");
		}
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
				"0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
				"--record-dir",
				dir,
			],
			{ DEPLOYER_PRIVATE_KEY: KEY },
		);
		assert.equal(core.code, 0, core.stderr);
		assert.match(core.stdout, /\+ giano\.paymaster\.proxy/);
		outputs.push(core.stdout, core.stderr);

		// The guided wizard's plan, with the key in its variable.
		const guided = await run(
			[
				"deploy/guided.ts",
				"--plan",
				"--chain",
				"base-sepolia",
				"--rpc",
				rpc,
				"--role-admin",
				"0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
			],
			{ CANONICAL_DEPLOYER_PRIVATE_KEY: KEY },
		);
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
		anvil.kill();
		rmSync(dir, { recursive: true, force: true });
	}
});
