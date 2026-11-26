import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
	existsSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";
import { TIMELOCKED_FUNCTION_NAMES } from "../timelock";
import {
	operatorInputProblems,
	SIGNED_RPC_COMMANDS,
	timelockCommand,
} from "./operator-commands";
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
					![
						"CHAIN_ID",
						"DEPLOY_CHAIN_ID",
						"CUSTOM_TEST_RPC_URL",
						// The settings the plans below must find missing.
						"PAYMASTER_ROLE_ADMIN",
						"DEPLOYER_PRIVATE_KEY",
						"SPONSORSHIP_SIGNER_ADDRESS",
						"SPONSORSHIP_SIGNER_KEY",
						"PAYMASTER_TENANTS",
						"ADMIN_API_KEY",
						"TENANT_SLUG",
						"WALLET_API_URL",
					].includes(key),
			),
		);
		const plan = (command: string) =>
			exec(
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
		for (const command of ["funding", "doctor"]) {
			const { stdout } = await plan(command);
			assert.match(stdout, /Custom test chain \(54321\)/);
			assert.match(stdout, /Read-only plan/);
		}
		// provision and sponsorship plan with the checks a real run makes first (G48 R3): they name every
		// setting the operator file lacks, before any read beyond the RPC identity check.
		const missing = {
			provision: [
				"PAYMASTER_ROLE_ADMIN",
				"DEPLOYER_PRIVATE_KEY",
				"SPONSORSHIP_SIGNER_ADDRESS",
				"PAYMASTER_TENANTS",
			],
			sponsorship: [
				"PAYMASTER_ROLE_ADMIN",
				"ADMIN_API_KEY",
				"TENANT_SLUG",
				"WALLET_API_URL",
			],
		};
		for (const [command, names] of Object.entries(missing))
			await assert.rejects(plan(command), (error: unknown) => {
				assert.ok(error && typeof error === "object" && "stderr" in error);
				const stderr = String(error.stderr);
				assert.match(stderr, /Correct the selected operator environment/);
				for (const name of names) assert.match(stderr, new RegExp(name));
				return true;
			});
		assert.equal(methods.length, 4);
		assert.ok(methods.every((method) => method === "eth_chainId"));
		assert.equal(existsSync(marker), false);

		// A blank PAYMASTER_ROLE_ADMIN= line leaves the profile's roleAdmin in force.
		const withAdmin = JSON.parse(readFileSync(profile, "utf8"));
		writeFileSync(
			profile,
			JSON.stringify({
				...withAdmin,
				roleAdmin: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
			}),
		);
		writeFileSync(
			operator,
			`CUSTOM_TEST_RPC_URL=http://127.0.0.1:${address.port}\nPAYMASTER_ROLE_ADMIN=\n`,
		);
		await assert.rejects(plan("provision"), (error: unknown) => {
			assert.ok(error && typeof error === "object" && "stderr" in error);
			const stderr = String(error.stderr);
			assert.match(stderr, /Correct the selected operator environment/);
			assert.doesNotMatch(stderr, /Persist ROLE_ADMIN/);
			return true;
		});
		writeFileSync(profile, JSON.stringify(withAdmin));
		const reads = methods.length;
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
			reads,
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

test("the operator environment is checked as a whole, and no message quotes a key", () => {
	const key =
		"0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
	const address = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
	const complete = {
		DEPLOYER_PRIVATE_KEY: key,
		SPONSORSHIP_SIGNER_ADDRESS: address,
		PAYMASTER_TENANTS: "demo:33333333-3333-4333-8333-333333333333",
	};
	assert.deepEqual(operatorInputProblems("provision", complete, address), []);
	// The address in any letter case.
	assert.deepEqual(
		operatorInputProblems("provision", complete, address.toLowerCase()),
		[],
	);

	const other = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";
	const wrongKey = operatorInputProblems("provision", complete, other);
	assert.equal(wrongKey.length, 1);
	assert.match(
		wrongKey[0],
		new RegExp(`key of ${address}, not of ROLE_ADMIN ${other}`),
	);

	// provision:paymaster (ethers) takes a key without 0x, so this check takes it too.
	assert.deepEqual(
		operatorInputProblems(
			"provision",
			{ ...complete, DEPLOYER_PRIVATE_KEY: key.slice(2) },
			address,
		),
		[],
	);

	// ethers refuses a stray space, so this check refuses it here, not later.
	assert.equal(
		operatorInputProblems(
			"provision",
			{ ...complete, DEPLOYER_PRIVATE_KEY: `${key} ` },
			address,
		).length,
		1,
	);

	const empty = operatorInputProblems("provision", {}, undefined);
	assert.equal(empty.length, 4);
	assert.ok(empty.every((problem) => !problem.includes(key)));

	// A blank line in the operator file counts as unset.
	assert.deepEqual(
		operatorInputProblems(
			"sponsorship",
			{ ADMIN_API_KEY: " ", TENANT_SLUG: "demo", WALLET_API_URL: "http://x" },
			address,
		),
		["Provide ADMIN_API_KEY."],
	);
	assert.deepEqual(operatorInputProblems("sponsorship", {}, "0x123"), [
		"ROLE_ADMIN 0x123 is not an address.",
		"Provide ADMIN_API_KEY.",
		"Provide TENANT_SLUG.",
		"Provide WALLET_API_URL.",
	]);
});
