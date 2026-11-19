import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";
import { TIMELOCKED_FUNCTION_NAMES } from "../timelock";
import { SIGNED_RPC_COMMANDS, timelockCommand } from "./operator-commands";
import type { ProfileFile } from "./profiles";

const exec = promisify(execFile);

test("all operator plans use the selected persisted profile, load dotenv without executing shell and issue only RPC reads", async () => {
	const methods: string[] = [];
	const server = createServer(async (req, res) => {
		let body = "";
		for await (const chunk of req) body += chunk;
		const request = JSON.parse(body);
		methods.push(request.method);
		res.setHeader("Content-Type", "application/json");
		res.end(
			JSON.stringify({ jsonrpc: "2.0", id: request.id, result: "0xd431" }),
		); // 54321: not a hardcoded supported-chain ID.
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const address = server.address();
	assert.ok(address && typeof address !== "string");
	const dir = mkdtempSync(join(tmpdir(), "giano-operations-"));
	try {
		const profile = join(dir, "custom.json");
		const operator = join(dir, "operator.env");
		const marker = join(dir, "must-not-exist");
		writeFileSync(
			profile,
			JSON.stringify({
				chainId: 54321,
				network: "testnet",
				name: "Custom test chain",
				rpcUrl: "https://example.test",
				rpcUrlEnv: "CUSTOM_TEST_RPC_URL",
				release: "v1",
				roleAdmin: null,
				minDeployerBalanceEth: "0.05",
				paymaster: {
					defaultFeeWei: "0",
					postOpGasAllowance: 40000,
					penaltyBps: 1000,
				},
			}),
		);
		writeFileSync(
			operator,
			`CUSTOM_TEST_RPC_URL=http://127.0.0.1:${address.port}\nNOT_A_SHELL_COMMAND=$(touch ${marker})\n`,
		);
		const env = Object.fromEntries(
			Object.entries(process.env).filter(
				([key]) =>
					!["CHAIN_ID", "DEPLOY_CHAIN_ID", "CUSTOM_TEST_RPC_URL"].includes(key),
			),
		);
		for (const command of ["funding", "provision", "sponsorship", "doctor"]) {
			const { stdout } = await exec(
				process.execPath,
				[
					"--import",
					"tsx",
					"deploy/operations.ts",
					command,
					"--config",
					profile,
					"--env-file",
					operator,
					"--plan",
				],
				{ cwd: new URL("..", import.meta.url), env },
			);
			assert.match(stdout, /Custom test chain \(54321\)/);
			assert.match(stdout, /Read-only plan/);
		}
		assert.equal(methods.length, 4);
		assert.ok(methods.every((method) => method === "eth_chainId"));
		assert.equal(existsSync(marker), false);
		writeFileSync(operator, "CHAIN_ID=1\n");
		await assert.rejects(
			exec(
				process.execPath,
				[
					"--import",
					"tsx",
					"deploy/operations.ts",
					"provision",
					"--config",
					profile,
					"--env-file",
					operator,
					"--plan",
				],
				{ cwd: new URL("..", import.meta.url), env },
			),
			(error: unknown) => {
				assert.ok(error && typeof error === "object" && "stderr" in error);
				assert.match(
					String(error.stderr),
					/CHAIN_ID differs from the selected chain profile/,
				);
				return true;
			},
		);
		assert.equal(
			methods.length,
			4,
			"conflicting chain input must fail before any workflow is invoked",
		);
	} finally {
		await new Promise<void>((resolve) => server.close(() => resolve()));
		rmSync(dir, { recursive: true, force: true });
	}
});

test("contracts:timelock and contracts:handoff pass --signed-rpc to deploy:cli only when asked", () => {
	const selected = {
		file: "/profiles/custom.json",
		id: "custom",
		profile: {
			chainId: 54321,
			release: "v3",
			timelock: {
				address: "0x4444444444444444444444444444444444444444",
				proposers: ["0x5555555555555555555555555555555555555555"],
				executors: [],
				delays: Object.fromEntries([
					["minDelay", 86400],
					...TIMELOCKED_FUNCTION_NAMES.map((name) => [name, 172800]),
				]),
			},
		},
	} as unknown as ProfileFile;
	const rpc = "http://127.0.0.1:1";
	for (const command of ["timelock", "handoff"] as const) {
		const unsigned = timelockCommand(command, selected, rpc, false);
		assert.equal(unsigned[0], command);
		assert.ok(!unsigned.includes("--signed-rpc"));
		assert.deepEqual(timelockCommand(command, selected, rpc, true), [
			...unsigned,
			"--signed-rpc",
		]);
	}
	// The launcher's hand-off always executes: its confirmation is the review.
	assert.ok(
		timelockCommand("handoff", selected, rpc, false).includes("--execute"),
	);
});

test("--signed-rpc is refused on a launcher command that sends no transaction, before anything else", async () => {
	for (const command of ["funding", "sponsorship", "doctor"]) {
		assert.ok(!SIGNED_RPC_COMMANDS.includes(command));
		await assert.rejects(
			exec(
				process.execPath,
				[
					"--import",
					"tsx",
					"deploy/operations.ts",
					command,
					"--config",
					"/does/not/exist.json",
					"--signed-rpc",
				],
				{ cwd: new URL("..", import.meta.url) },
			),
			(error: unknown) => {
				assert.ok(error && typeof error === "object" && "stderr" in error);
				assert.match(
					String(error.stderr),
					new RegExp(
						`--signed-rpc applies to provision, timelock, handoff: .* ${command} sends none`,
					),
				);
				return true;
			},
		);
	}
});
