// Rebuild off-chain simulation/test artifacts from the pinned v0.9 standard JSON input.
// SOLC=/path/to/solc-0.8.28 node scripts/generate-entrypoint-artifacts.mjs [--check]
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";

import { homedir } from "node:os";
import { join } from "node:path";

const compiler =
	process.env.SOLC ??
	[
		join(homedir(), ".svm"),
		join(homedir(), ".local/share/svm"),
		join(homedir(), "Library/Application Support/svm"),
	]
		.map((root) => join(root, "0.8.28/solc-0.8.28"))
		.find(existsSync) ??
	"solc";
const root = new URL("../vendor/account-abstraction/", import.meta.url);
const output = JSON.parse(
	execFileSync(compiler, ["--standard-json"], {
		input: readFileSync(new URL("simulation-input.json", root)),
		maxBuffer: 32 * 1024 * 1024,
		encoding: "utf8",
	}),
);
const errors = (output.errors ?? []).filter((e) => e.severity === "error");
if (errors.length)
	throw new Error(errors.map((e) => e.formattedMessage).join("\n"));
const entryPoint = JSON.parse(
	readFileSync(new URL("artifacts/EntryPoint.json", root)),
);
if (
	`0x${output.contracts["contracts/core/EntryPoint.sol"].EntryPoint.evm.bytecode.object}` !==
	entryPoint.bytecode
)
	throw new Error(
		"Pinned source no longer reproduces the verified canonical EntryPoint creation code",
	);
for (const [name, directory] of [
	["EntryPointSimulations", "core"],
	["SenderCreator", "core"],
	["SimpleAccountFactory", "accounts"],
	["SimpleAccount", "accounts"],
	["VerifyingPaymaster", "test"],
]) {
	const artifact = output.contracts[`contracts/${directory}/${name}.sol`][name];
	let runtime = artifact.evm.deployedBytecode.object;
	if (name === "SenderCreator") {
		for (const refs of Object.values(
			artifact.evm.deployedBytecode.immutableReferences,
		)) {
			for (const { start, length } of refs) {
				const address = "433709009b8330fda32311df1c2afa402ed8d009".padStart(
					length * 2,
					"0",
				);
				runtime =
					runtime.slice(0, start * 2) +
					address +
					runtime.slice((start + length) * 2);
			}
		}
	}
	const text = `${JSON.stringify({ abi: artifact.abi, bytecode: `0x${artifact.evm.bytecode.object}`, deployedBytecode: `0x${runtime}` }, null, 2)}\n`;
	const target = new URL(`artifacts/${name}.json`, root);
	if (process.argv.includes("--check")) {
		if (readFileSync(target, "utf8") !== text)
			throw new Error(`${name} artifact is stale`);
	} else writeFileSync(target, text);
}
console.log(
	"EntryPoint v0.9 creation code and simulation/test artifacts reproduce",
);
