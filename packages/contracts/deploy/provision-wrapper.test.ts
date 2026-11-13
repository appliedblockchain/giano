/**
 * The provisioning wrapper (deploy/contracts/provision-paymaster.sh) refuses development shortcuts on
 * a mainnet and asks for an explicit role topology. Every case here stops before any chain call.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
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
			ROLE_HOLDER_PAUSER: ADDRESS,
		}).out,
		/needs each tenant's own TENANT_WITHDRAW_ADDRESS/,
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
