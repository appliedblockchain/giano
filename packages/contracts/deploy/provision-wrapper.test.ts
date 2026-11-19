/**
 * The provisioning wrapper (deploy/contracts/provision-paymaster.sh) refuses development shortcuts on
 * a mainnet and asks for an explicit role topology. Every case here stops before any chain call.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
	chmodSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { REPO_ROOT } from "./profiles";

const KEY =
	"0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const ADDRESS = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

function wrapper(env: Record<string, string>): { code: number; out: string } {
	const run = spawnSync(
		"bash",
		[join(REPO_ROOT, "deploy/contracts/provision-paymaster.sh")],
		{
			cwd: REPO_ROOT,
			env: {
				PATH: process.env.PATH,
				HOME: process.env.HOME,
				GIANO_PROFILE_LOADED: "1",
				CHAIN_ID: "8453",
				RPC_URL: "http://127.0.0.1:1",
				DEPLOYER_PRIVATE_KEY: KEY,
				SPONSORSHIP_PAYMASTER_ADDRESS: ADDRESS,
				PAYMASTER_TENANTS: "demo:33333333-3333-4333-8333-333333333333",
				...env,
			},
			encoding: "utf8",
		},
	);
	return { code: run.status ?? 1, out: `${run.stdout}${run.stderr}` };
}

test("the sponsorship signer is given by address", () => {
	const missing = wrapper({});
	assert.notEqual(missing.code, 0);
	assert.match(missing.out, /set SPONSORSHIP_SIGNER_ADDRESS/);
});

test("the signer's address and key, when both are given, must be the same signer", () => {
	const other = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";
	const drifted = wrapper({
		SPONSORSHIP_SIGNER_ADDRESS: other,
		SPONSORSHIP_SIGNER_KEY: KEY,
	});
	assert.notEqual(drifted.code, 0);
	assert.match(
		drifted.out,
		new RegExp(
			`SPONSORSHIP_SIGNER_ADDRESS ${other} is not the address of SPONSORSHIP_SIGNER_KEY \\(${ADDRESS}\\)`,
		),
	);
	// Matching (in any letter case) passes this check and stops at the next one, the role topology.
	const matching = wrapper({
		SPONSORSHIP_SIGNER_ADDRESS: ADDRESS.toLowerCase(),
		SPONSORSHIP_SIGNER_KEY: KEY,
	});
	assert.doesNotMatch(matching.out, /is not the address of/);
	assert.match(matching.out, /name the role holders/);
});

/** Six distinct holders, one per immediate role. */
const SIX_HOLDERS = Object.fromEntries(
	[
		"SIGNER_ADMIN",
		"PARAM_ADMIN",
		"PAUSER",
		"STAKE_ADMIN",
		"TENANT_ADMIN",
		"FEE_COLLECTOR",
	].map((role, i) => [
		`ROLE_HOLDER_${role}`,
		`0x${String(i + 1).padStart(40, "0")}`,
	]),
);

test("a mainnet refuses the signer's key, every role on one address, and a defaulted withdrawal address", () => {
	const mainnet = { GIANO_NETWORK: "mainnet" };
	assert.match(
		wrapper({ ...mainnet, SPONSORSHIP_SIGNER_KEY: KEY }).out,
		/never its key/,
	);
	assert.match(
		wrapper({
			...mainnet,
			SPONSORSHIP_SIGNER_ADDRESS: ADDRESS,
			PAYMASTER_GRANT_ALL_TO: ADDRESS,
		}).out,
		/a mainnet refuses it/,
	);
	assert.match(
		wrapper({
			...mainnet,
			SPONSORSHIP_SIGNER_ADDRESS: ADDRESS,
			...SIX_HOLDERS,
		}).out,
		/needs each tenant's own TENANT_WITHDRAW_ADDRESS/,
	);
});

test("a mainnet names all six role holders, each on its own address (G42 R1)", () => {
	const mainnet = {
		GIANO_NETWORK: "mainnet",
		SPONSORSHIP_SIGNER_ADDRESS: ADDRESS,
	};
	const partial = wrapper({ ...mainnet, ROLE_HOLDER_PAUSER: ADDRESS });
	assert.notEqual(partial.code, 0);
	assert.match(
		partial.out,
		/missing: ROLE_HOLDER_SIGNER_ADMIN ROLE_HOLDER_PARAM_ADMIN ROLE_HOLDER_STAKE_ADMIN ROLE_HOLDER_TENANT_ADMIN ROLE_HOLDER_FEE_COLLECTOR/,
	);
	// The same address twice, in any letter case.
	const shared = wrapper({
		...mainnet,
		...SIX_HOLDERS,
		ROLE_HOLDER_FEE_COLLECTOR: ADDRESS,
		ROLE_HOLDER_PAUSER: ADDRESS.toLowerCase(),
	});
	assert.notEqual(shared.code, 0);
	assert.match(
		shared.out,
		new RegExp(`used for more than one role: ${ADDRESS.toLowerCase()}`),
	);
	// Nor may a holder be the operator key, which holds ROLE_ADMIN until the hand-off (#298 review).
	const operator = wrapper({
		...mainnet,
		...SIX_HOLDERS,
		ROLE_HOLDER_PAUSER: ADDRESS.toLowerCase(),
	});
	assert.notEqual(operator.code, 0);
	assert.match(
		operator.out,
		new RegExp(`${ADDRESS} is the operator key \\(DEPLOYER_PRIVATE_KEY\\)`),
	);
	// A testnet may still name only some of them.
	assert.doesNotMatch(
		wrapper({
			GIANO_NETWORK: "testnet",
			SPONSORSHIP_SIGNER_ADDRESS: ADDRESS,
			ROLE_HOLDER_PAUSER: ADDRESS,
			ROLE_HOLDER_FEE_COLLECTOR: ADDRESS,
		}).out,
		/missing:|more than one role/,
	);
});

test("the role topology is explicit: holders per role, or the development grant-all", () => {
	const none = wrapper({
		GIANO_NETWORK: "testnet",
		SPONSORSHIP_SIGNER_ADDRESS: ADDRESS,
	});
	assert.notEqual(none.code, 0);
	assert.match(none.out, /name the role holders/);
	assert.match(
		wrapper({
			GIANO_NETWORK: "testnet",
			SPONSORSHIP_SIGNER_ADDRESS: ADDRESS,
			PAYMASTER_GRANT_ALL_TO: ADDRESS,
			ROLE_HOLDER_PAUSER: ADDRESS,
		}).out,
		/not both/,
	);
});

function sponsorshipWrapper(env: Record<string, string>): {
	code: number;
	out: string;
} {
	const run = spawnSync(
		"bash",
		[join(REPO_ROOT, "deploy/contracts/provision-sponsorship.sh")],
		{
			cwd: REPO_ROOT,
			env: {
				PATH: process.env.PATH,
				HOME: process.env.HOME,
				GIANO_PROFILE_LOADED: "1",
				CHAIN_ID: "84532",
				RPC_URL: "http://127.0.0.1:1",
				SPONSORSHIP_PAYMASTER_ADDRESS: ADDRESS,
				TENANT_SLUG: "demo",
				ADMIN_API_KEY: "demo-admin-key",
				WALLET_API_URL: "http://127.0.0.1:1",
				...env,
			},
			encoding: "utf8",
		},
	);
	return { code: run.status ?? 1, out: `${run.stdout}${run.stderr}` };
}

test("sponsorship on a chain without the demo ERC-20 needs the tenant's contracts", () => {
	const none = sponsorshipWrapper({});
	assert.notEqual(none.code, 0);
	assert.match(none.out, /set SPONSOR_ALLOWLIST/);
	assert.doesNotMatch(none.out, /Installing sponsorship rules/);

	const bad = sponsorshipWrapper({ SPONSOR_ALLOWLIST: `${ADDRESS},0x1234` });
	assert.notEqual(bad.code, 0);
	assert.match(bad.out, /'0x1234' is not a contract address/);
});

/**
 * The pnpm commands the wrapper runs, with GIANO_SIGNED_RPC set to `signedRpc`. A stand-in pnpm
 * records them and runs only the key derivation (`pnpm … exec node -e`) with the real pnpm, so no
 * chain call is made.
 */
function pnpmCommands(signedRpc: string): string[] {
	const realPnpm = spawnSync("bash", ["-c", "command -v pnpm"], {
		encoding: "utf8",
	}).stdout.trim();
	assert.ok(realPnpm, "pnpm must be on PATH");
	const dir = mkdtempSync(join(tmpdir(), "giano-provision-wrapper-"));
	try {
		const log = join(dir, "pnpm.log");
		writeFileSync(
			join(dir, "pnpm"),
			`#!/usr/bin/env bash\nif [ "\${3:-}" = "exec" ]; then exec "${realPnpm}" "$@"; fi\nprintf '%s\\n' "$*" >> "${log}"\n`,
		);
		chmodSync(join(dir, "pnpm"), 0o755);
		const { code, out } = wrapper({
			PATH: `${dir}:${process.env.PATH}`,
			CHAIN_NAME: "Custom test chain",
			FACTORY_ADDRESS: ADDRESS,
			SPONSORSHIP_SIGNER_ADDRESS: ADDRESS,
			PAYMASTER_GRANT_ALL_TO: ADDRESS,
			GIANO_SIGNED_RPC: signedRpc,
		});
		assert.equal(code, 0, out);
		return readFileSync(log, "utf8").trim().split("\n");
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
}

test("the launcher's --signed-rpc (GIANO_SIGNED_RPC=1) reaches provision:paymaster, and only then", () => {
	const provisions = (signedRpc: string) =>
		pnpmCommands(signedRpc).filter((line) =>
			line.includes("provision:paymaster"),
		);
	const signed = provisions("1");
	assert.equal(signed.length, 1);
	assert.match(signed[0], / --signed-rpc$/);
	const unsigned = provisions("");
	assert.equal(unsigned.length, 1);
	assert.doesNotMatch(unsigned[0], /--signed-rpc/);
});
