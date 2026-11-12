import assert from "node:assert/strict";
import {
	existsSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
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
import { COMMITTED_DEPLOYMENTS_DIR, type DeploymentRecord } from "./records";
import { latestRelease } from "./release";

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

test("a profile declares its network class, and only mainnet or testnet", () => {
	assert.equal(base.profile.network, "testnet");
	const { network: _network, ...withoutClass } = base.profile;
	assert.equal(profileSchema.safeParse(withoutClass).success, false);
	for (const network of ["local", "Mainnet", "devnet", ""])
		assert.equal(
			profileSchema.safeParse({ ...base.profile, network }).success,
			false,
			network,
		);
	assert.equal(
		profileSchema.safeParse({ ...base.profile, network: "mainnet" }).success,
		true,
	);
});

test("a missing or unknown class is refused with the accepted classes named", () => {
	const dir = mkdtempSync(join(tmpdir(), "giano-profile-class-"));
	try {
		const file = join(dir, "no-class.json");
		const { network: _network, ...withoutClass } = base.profile;
		writeFileSync(file, JSON.stringify(withoutClass));
		assert.throws(
			() => loadProfile({ config: file }),
			/network \(mainnet or testnet\)/,
		);
		writeFileSync(file, JSON.stringify({ ...base.profile, network: "beta" }));
		assert.throws(
			() => loadProfile({ config: file }),
			/network \(mainnet or testnet\)/,
		);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test("address overrides accept the overridable contracts only, as nonzero addresses", () => {
	const valid = profileSchema.safeParse({
		...base.profile,
		addresses: {
			paymasterProxy: "0x2222222222222222222222222222222222222222",
			walletImplementation: "0x3333333333333333333333333333333333333333",
		},
	});
	assert.equal(valid.success, true);
	assert.equal(
		valid.data?.addresses?.paymasterProxy,
		"0x2222222222222222222222222222222222222222",
	);
	for (const addresses of [
		{ testErc20: "0x2222222222222222222222222222222222222222" },
		// The timelock's address lives in `timelock.address` only.
		{ timelock: "0x4444444444444444444444444444444444444444" },
		{ paymaster: "0x2222222222222222222222222222222222222222" },
		{ factory: "0x0000000000000000000000000000000000000000" },
		{ factory: "not an address" },
	])
		assert.equal(
			profileSchema.safeParse({ ...base.profile, addresses }).success,
			false,
			JSON.stringify(addresses),
		);
});

/**
 * A profile's release is what every new wallet on its chain starts on, for good: the factory's
 * implementation is immutable. Until the chain has a committed record, the profile must pin the
 * newest release, so a stale pin cannot ship; once deployed, it stays the release the record holds.
 */
test("shipped profiles pin the newest release until deployed, then the release they were deployed from", () => {
	const newest = latestRelease();
	for (const id of listProfiles()) {
		const { profile } = loadProfile({ chain: id });
		const record = join(COMMITTED_DEPLOYMENTS_DIR, `${profile.chainId}.json`);
		const deployedFrom = existsSync(record)
			? (JSON.parse(readFileSync(record, "utf8")) as DeploymentRecord).contracts
					.walletImplementation?.release
			: undefined;
		assert.equal(
			profile.release,
			deployedFrom ?? newest,
			deployedFrom
				? `${id}: chain ${profile.chainId} was deployed from ${deployedFrom}; its profile must keep that release`
				: `${id} pins ${profile.release}, but ${newest} is the newest release and the chain is not deployed yet`,
		);
	}
});
