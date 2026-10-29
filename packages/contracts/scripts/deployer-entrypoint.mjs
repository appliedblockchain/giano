#!/usr/bin/env node
// Entry point of the giano-contracts-deployer image (Dockerfile.deployer). No shell: the image's
// runtime has none (ABIP-2), so the CLI runs as a child `node` process with an argument array.
//
//   RPC_URL, CHAIN_ID          the chain (CHAIN_ID is checked against what the endpoint reports)
//   DEPLOYER_PRIVATE_KEY       the canonical deployer's key (packages/contracts/deploy/config.ts)
//   DEPLOYER_IMPERSONATE=true  local chains (31337/31338) only: impersonate the canonical deployer
//                              instead of signing; the CLI refuses it on any other chain
//   ROLE_ADMIN                 the paymaster's sole ROLE_ADMIN; a TimelockController in production
//   RELEASE                    optional; the latest release by default
//   DEPLOY_TESTING=true        also deploy PrivateERC20 + PermissivePaymaster (never on 8453/84532/11155111)
//   PAYMASTER_FUND_ETH         the test paymaster's initial EntryPoint deposit (default 0)
//   OUT_DIR                    where the record and the registry JSON go (default /out)

import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const CLI = resolve(
	dirname(fileURLToPath(import.meta.url)),
	"..",
	"dist-deployer",
	"cli.mjs",
);

const env = process.env;
function required(name, why = "") {
	if (!env[name]) {
		console.error(`${name} is required${why}`);
		process.exit(1);
	}
	return env[name];
}

const rpcUrl = required("RPC_URL");
const chainId = Number(required("CHAIN_ID"));
const impersonate = env.DEPLOYER_IMPERSONATE === "true";
if (!impersonate) required("DEPLOYER_PRIVATE_KEY", " (the canonical deployer)");
const roleAdmin = required("ROLE_ADMIN", " (the paymaster ROLE_ADMIN)");
const outDir = env.OUT_DIR || "/out";
const common = [
	"--rpc",
	rpcUrl,
	"--record-dir",
	outDir,
	...(env.RELEASE ? ["--release", env.RELEASE] : []),
];
if (impersonate) common.push("--impersonate");

function cli(args) {
	const { status, error } = spawnSync(process.execPath, [CLI, ...args], {
		stdio: "inherit",
	});
	if (error) throw error;
	if (status !== 0) process.exit(status ?? 1);
}

// The release defaults to the latest; RELEASE pins one. The record lands in OUT_DIR, so a re-run
// against the same volume picks up where it left off.
cli(["core", "--role-admin", roleAdmin, ...common]);

if (env.DEPLOY_TESTING === "true") {
	cli([
		"testing",
		"--holder",
		roleAdmin,
		"--owner",
		roleAdmin,
		"--fund-eth",
		env.PAYMASTER_FUND_ETH || "0",
		...common,
	]);
}

// The registry entry for this chain in the shared schema (GianoDeployment in addresses.ts).
const record = JSON.parse(readFileSync(`${outDir}/${chainId}.json`, "utf8"));
if (record.chainId !== chainId) {
	throw new Error(
		`the endpoint is chain ${record.chainId}, not CHAIN_ID=${chainId}`,
	);
}
const c = record.contracts;
const entry = {
	chainId,
	entryPoint: "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
	factory: c.factory.address,
	implementation: c.walletImplementation.address,
	sponsorshipPaymaster: c.paymasterProxy.address,
	sponsorshipPaymasterImplementation: c.paymasterImplementation.address,
	...(c.testPaymaster ? { testPaymaster: c.testPaymaster.address } : {}),
	...(c.testErc20 ? { testErc20: c.testErc20.address } : {}),
};
const path = `${outDir}/giano-addresses.${chainId}.json`;
writeFileSync(path, JSON.stringify(entry, null, 2));
console.log(`wrote ${path}`);
