import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
	listProfiles,
	loadProfile,
	paymasterParams,
	profileSchema,
	savePublicChoices,
} from "./profiles";

const base = loadProfile({ chain: "base-sepolia" });

test("persisted supported chain profiles load without a network list in the tooling", () => {
	assert.ok(listProfiles().includes("base-sepolia"));
	assert.ok(listProfiles().includes("ethereum-sepolia"));
	assert.equal(base.profile.chainId, 84532);
	assert.equal(
		loadProfile({ chain: "ethereum-sepolia" }).profile.chainId,
		11155111,
	);
	assert.equal(
		paymasterParams(base.profile).defaultFeeWei,
		100_000_000_000_000n,
	);
});

test("new EVM networks and paymaster settings are data, not code changes", () => {
	const dir = mkdtempSync(join(tmpdir(), "giano-profile-"));
	try {
		const file = join(dir, "another-chain.json");
		writeFileSync(
			file,
			JSON.stringify({
				...base.profile,
				chainId: 54321,
				name: "Another chain",
				rpcUrlEnv: "ANOTHER_RPC_URL",
				minDeployerBalanceEth: "0.1",
				paymaster: {
					defaultFeeWei: "0",
					postOpGasAllowance: 50000,
					penaltyBps: 500,
				},
			}),
		);
		const loaded = loadProfile({ config: file });
		assert.equal(loaded.profile.chainId, 54321);
		assert.equal(paymasterParams(loaded.profile).defaultFeeWei, 0n);
		assert.equal(paymasterParams(loaded.profile).penaltyBps, 500);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test("profiles refuse ambiguous selection, path traversal, unknown secret fields and invalid settings", () => {
	for (const options of [
		{},
		{ chain: "../base-sepolia" },
		{ chain: "__proto__" },
		{ chain: "base-sepolia", config: "anything" },
	])
		assert.throws(() => loadProfile(options));
	for (const change of [
		{ privateKey: "sensitive" },
		{ chainId: 0 },
		{ rpcUrl: "invalid" },
		{ rpcUrl: "https://user:secret@example.test" },
		{ rpcUrl: "https://example.test/?apiKey=secret" },
		{ release: "dev" },
		{ roleAdmin: "0x0000000000000000000000000000000000000000" },
		{ minDeployerBalanceEth: "0" },
		{ minDeployerBalanceEth: "bad" },
		{
			paymaster: {
				defaultFeeWei: "bad",
				postOpGasAllowance: 40000,
				penaltyBps: 1000,
			},
		},
		{
			paymaster: {
				defaultFeeWei: "-1",
				postOpGasAllowance: 40000,
				penaltyBps: 1000,
			},
		},
	])
		assert.equal(
			profileSchema.safeParse({ ...base.profile, ...change }).success,
			false,
		);
});

test("save public choices preserves chain identity and RPC reference, never runtime credentials", () => {
	const dir = mkdtempSync(join(tmpdir(), "giano-profile-save-"));
	const previous = process.env[base.profile.rpcUrlEnv];
	try {
		process.env[base.profile.rpcUrlEnv] =
			"https://provider.test/SECRET_RUNTIME_KEY";
		const selected = { ...base, file: join(dir, "profile.json") };
		savePublicChoices(
			selected,
			"0x1111111111111111111111111111111111111111",
			"v2",
		);
		const text = readFileSync(selected.file, "utf8");
		const saved = loadProfile({ config: selected.file });
		assert.equal(saved.profile.release, "v2");
		assert.equal(
			saved.profile.roleAdmin,
			"0x1111111111111111111111111111111111111111",
		);
		assert.equal(saved.profile.chainId, base.profile.chainId);
		assert.equal(saved.profile.rpcUrl, base.profile.rpcUrl);
		assert.equal(saved.profile.rpcUrlEnv, base.profile.rpcUrlEnv);
		assert.doesNotMatch(text, /SECRET_RUNTIME_KEY/);
	} finally {
		if (previous === undefined) delete process.env[base.profile.rpcUrlEnv];
		else process.env[base.profile.rpcUrlEnv] = previous;
		rmSync(dir, { recursive: true, force: true });
	}
});
