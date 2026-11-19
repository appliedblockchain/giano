/**
 * The deployer image's entrypoint (scripts/deployer-entrypoint.mjs) lists the private test token in
 * its registry JSON exactly where `testing` deploys and checks it (privateTestErc20Wanted): with
 * DEPLOY_TESTING=true, on every local chain the CLI knows (LOCAL_CHAIN_IDS), and on a remote chain
 * whose profile opts in. The entrypoint is a plain .mjs file and cannot import those rules, so this
 * test keeps its copy in step.
 *
 * It runs a copy of the entrypoint next to a stand-in CLI that records its arguments and sends
 * nothing. The seeded record lists every fixture, as a reused volume or a committed record can.
 */
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
	copyFileSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { promisify } from "node:util";
import { LOCAL_CHAIN_IDS } from "./config";
import { privateTestErc20Wanted } from "./deploy";

const root = mkdtempSync(join(tmpdir(), "giano-deployer-entrypoint-"));
after(() => rmSync(root, { recursive: true, force: true }));
mkdirSync(join(root, "scripts"));
mkdirSync(join(root, "dist-deployer"));
copyFileSync(
	join(import.meta.dirname, "..", "scripts", "deployer-entrypoint.mjs"),
	join(root, "scripts", "deployer-entrypoint.mjs"),
);
// Appends its arguments, one JSON line per run, to $CLI_LOG.
writeFileSync(
	join(root, "dist-deployer", "cli.mjs"),
	[
		'import { appendFileSync } from "node:fs";',
		'appendFileSync(process.env.CLI_LOG, JSON.stringify(process.argv.slice(2)) + "\\n");',
		"",
	].join("\n"),
);

const address = (n: number) => `0x${String(n).repeat(40)}`;

const REMOTE = 19877;

async function run(
	chainId: number,
	options: { testing: boolean; optIn?: boolean },
): Promise<{ commands: string[]; registry: Record<string, unknown> }> {
	const outDir = mkdtempSync(join(root, "out-"));
	const log = join(outDir, "cli.log");
	const contracts = Object.fromEntries(
		[
			"factory",
			"walletImplementation",
			"paymasterProxy",
			"paymasterImplementation",
			"testErc20",
			"testPaymaster",
			"privateTestErc20",
		].map((key, i) => [key, { address: address(i + 1) }]),
	);
	await promisify(execFile)(
		process.execPath,
		[join(root, "scripts", "deployer-entrypoint.mjs")],
		{
			env: {
				PATH: process.env.PATH,
				RPC_URL: "http://127.0.0.1:1",
				CHAIN_ID: String(chainId),
				ROLE_ADMIN: address(9),
				OUT_DIR: outDir,
				CLI_LOG: log,
				DEPLOYMENT_RECORD_JSON: JSON.stringify({ chainId, contracts }),
				...(options.optIn === undefined
					? {}
					: {
							CHAIN_PROFILE_JSON: JSON.stringify({
								chainId,
								privateTestErc20: options.optIn,
							}),
						}),
				...(options.testing ? { DEPLOY_TESTING: "true" } : {}),
			},
		},
	);
	const commands = readFileSync(log, "utf8")
		.trim()
		.split("\n")
		.map((line) => (JSON.parse(line) as string[])[0]);
	const registry = JSON.parse(
		readFileSync(join(outDir, `giano-addresses.${chainId}.json`), "utf8"),
	) as Record<string, unknown>;
	return { commands, registry };
}

test("with DEPLOY_TESTING, every local chain lists the private test token, as testing deploys it there", async () => {
	for (const chainId of LOCAL_CHAIN_IDS) {
		assert.equal(privateTestErc20Wanted({ local: true }), true);
		const { commands, registry } = await run(chainId, { testing: true });
		assert.deepEqual(commands, ["core", "testing"], String(chainId));
		assert.equal(registry.privateTestErc20, address(7), String(chainId));
	}
});

test("a remote chain lists it only when its profile opts in", async () => {
	for (const optIn of [undefined, false, true]) {
		const { commands, registry } = await run(REMOTE, { testing: true, optIn });
		assert.deepEqual(commands, ["core", "testing"]);
		assert.equal(
			registry.privateTestErc20,
			privateTestErc20Wanted({ local: false, optIn }) ? address(7) : undefined,
			`optIn ${optIn}`,
		);
	}
});

test("without DEPLOY_TESTING, testing does not run and the private test token is not listed", async () => {
	for (const chainId of [LOCAL_CHAIN_IDS[0], REMOTE]) {
		const { commands, registry } = await run(chainId, {
			testing: false,
			optIn: true,
		});
		assert.deepEqual(commands, ["core"]);
		assert.equal(registry.privateTestErc20, undefined, String(chainId));
	}
});
