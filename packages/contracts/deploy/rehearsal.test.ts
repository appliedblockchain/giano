/**
 * Rehearsals (deploy/config.ts `activateRehearsal`): a stand-in deployer answers for the canonical one
 * only on an anvil fork, and nothing a rehearsal writes reaches the committed records or the registry.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, test } from "node:test";
import {
	activateRehearsal,
	classDeployer,
	DEPLOYERS,
	isClassDeployer,
	REHEARSAL_DEPLOYER_ENV,
	rehearsalDeployerAddress,
	resetRehearsal,
} from "./config";
import { COMMITTED_DEPLOYMENTS_DIR, REHEARSAL_DIR } from "./records";

const STAND_IN = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const env = { [REHEARSAL_DEPLOYER_ENV]: STAND_IN };

/** A node answering anvil_nodeInfo with `forkUrl`, as anvil 1.7.1 does. */
function anvil(forkUrl: string | null) {
	return {
		request: async ({ method }: { method: string }) => {
			assert.equal(method, "anvil_nodeInfo");
			return {
				environment: { chainId: 84532 },
				forkConfig: { forkUrl, forkBlockNumber: forkUrl ? 1 : null },
			};
		},
	};
}

/** A public RPC: no anvil_ namespace. */
const publicRpc = {
	request: async () => {
		throw new Error(
			"the method anvil_nodeInfo does not exist/is not available",
		);
	},
};

afterEach(() => resetRehearsal());

test("without the variable there is no rehearsal, whatever the node is", async () => {
	assert.equal(
		await activateRehearsal(anvil("https://sepolia.base.org"), {}),
		null,
	);
	assert.equal(rehearsalDeployerAddress(), null);
	assert.equal(classDeployer("testnet"), DEPLOYERS.testnet);
});

test("a fork accepts the stand-in, which then answers for every non-local class", async () => {
	assert.equal(
		await activateRehearsal(anvil("https://sepolia.base.org"), env),
		STAND_IN,
	);
	assert.equal(classDeployer("testnet"), STAND_IN);
	assert.equal(classDeployer("mainnet"), STAND_IN);
	assert.equal(classDeployer("local"), DEPLOYERS.local);
	// The role-admin guard refuses the stand-in like any deployer.
	assert.equal(isClassDeployer(STAND_IN), true);
});

test("a plain anvil (no fork) refuses the stand-in", async () => {
	await assert.rejects(
		activateRehearsal(anvil(null), env),
		/accepted only on an anvil fork/,
	);
	assert.equal(classDeployer("testnet"), DEPLOYERS.testnet);
});

test("a public RPC refuses the stand-in", async () => {
	await assert.rejects(
		activateRehearsal(publicRpc, env),
		/accepted only on an anvil fork/,
	);
	assert.equal(rehearsalDeployerAddress(), null);
});

test("the stand-in must be a valid throwaway address", async () => {
	const fork = anvil("https://sepolia.base.org");
	await assert.rejects(
		activateRehearsal(fork, { [REHEARSAL_DEPLOYER_ENV]: "not-an-address" }),
		/is not an address/,
	);
	await assert.rejects(
		activateRehearsal(fork, { [REHEARSAL_DEPLOYER_ENV]: DEPLOYERS.local }),
		/throwaway address/,
	);
});

/** Evaluates `code` in a fresh process with `extraEnv`, the way a rehearsal's child commands start. */
function inChild(code: string, extraEnv: Record<string, string>): string {
	return execFileSync(
		process.execPath,
		["--import", "tsx", "--input-type=module", "-e", code],
		{
			cwd: join(import.meta.dirname, ".."),
			env: { ...process.env, ...extraEnv },
			encoding: "utf8",
		},
	).trim();
}

test("a rehearsal process reads and writes records under deploy/rehearsal, never deployments/", () => {
	const code =
		"import { DEPLOYMENTS_DIR } from './deploy/records.ts'; console.log(DEPLOYMENTS_DIR);";
	assert.equal(inChild(code, env), join(REHEARSAL_DIR, "records"));
	assert.equal(
		inChild(code, { [REHEARSAL_DEPLOYER_ENV]: "" }),
		COMMITTED_DEPLOYMENTS_DIR,
	);
});

test("the published registry is built from the committed records, even in a rehearsal process", () => {
	const generated = inChild(
		"import { generateRegistry } from './scripts/generate-addresses.ts'; process.stdout.write(generateRegistry().text);",
		env,
	);
	assert.equal(
		generated,
		readFileSync(
			join(import.meta.dirname, "..", "addresses.ts"),
			"utf8",
		).trim(),
	);
});
