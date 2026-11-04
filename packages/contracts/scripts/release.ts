/**
 * Contract releases (see deploy/release.ts).
 *
 *   pnpm release:cut <version>   build with Foundry and freeze releases/<version>/
 *   pnpm release:verify          recompile every release's standard-JSON input with plain solc and
 *                                check it reproduces the release's creation code and runtime record
 *   pnpm release:runtime         record the runtime codehash of RUNTIME_CONTRACTS in a release that
 *                                predates it; derived from the frozen input, never a fresh build
 *   pnpm release:status          say which contracts differ from the latest release
 *
 * `verify` needs the release's solc. It uses $SOLC if set, otherwise the binary Foundry installs
 * (~/.svm/<version>/solc-<version>), which any `forge build` on this repo provides.
 */
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { type Hex, keccak256 } from "viem";
import {
	latestRelease,
	listReleases,
	loadRelease,
	RELEASE_CONTRACTS,
	RELEASES_DIR,
	type Release,
	type ReleaseContract,
	type ReleaseRuntime,
	RUNTIME_CONTRACTS,
} from "../deploy/release";

const pkgRoot = path.resolve(import.meta.dirname, "..");

/** Only bytecode is needed to check a release; solc's output does not depend on the selection. */
const OUTPUT_SELECTION = { "*": { "*": ["evm.bytecode.object"] } };

/** What `verify` and `runtime` ask solc for: the creation code, and the runtime code with its immutables. */
const VERIFY_SELECTION = {
	"*": {
		"*": [
			"evm.bytecode.object",
			"evm.deployedBytecode.object",
			"evm.deployedBytecode.immutableReferences",
		],
	},
};

type StandardInput = {
	language: string;
	sources: Record<string, unknown>;
	settings: Record<string, unknown>;
};
type BuildInfo = {
	solcLongVersion: string;
	input: StandardInput;
	output: {
		contracts: Record<
			string,
			Record<
				string,
				{
					evm: {
						bytecode: { object: string };
						deployedBytecode?: {
							object: string;
							immutableReferences?: Record<
								string,
								{ start: number; length: number }[]
							>;
						};
					};
				}
			>
		>;
	};
};

function hex(object: string): Hex {
	return (object.startsWith("0x") ? object : `0x${object}`) as Hex;
}

/** A clean Foundry build of src/ (no tests or scripts), returned as solc's input and output. */
function foundryBuild(): BuildInfo {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "giano-release-"));
	try {
		execFileSync(
			"forge",
			[
				"build",
				"--skip",
				"test",
				"--skip",
				"script",
				"--force",
				"--build-info",
				"--build-info-path",
				dir,
			],
			{
				cwd: pkgRoot,
				stdio: ["ignore", "ignore", "inherit"],
			},
		);
		const files = fs.readdirSync(dir).filter((f) => f.endsWith(".json"));
		if (files.length !== 1)
			throw new Error(
				`expected one build-info file from forge, got ${files.length}`,
			);
		return JSON.parse(
			fs.readFileSync(path.join(dir, files[0]), "utf8"),
		) as BuildInfo;
	} finally {
		fs.rmSync(dir, { recursive: true, force: true });
	}
}

/**
 * Creation code of `names` (default: every contract a release carries today). An older release
 * may carry fewer — v1 predates GianoTimelock — so `verify` passes the release's own list.
 */
function creationCodes(
	output: BuildInfo["output"],
	names: readonly ReleaseContract[] = Object.keys(
		RELEASE_CONTRACTS,
	) as ReleaseContract[],
): Record<ReleaseContract, Hex> {
	const codes = {} as Record<ReleaseContract, Hex>;
	for (const name of names) {
		const source = RELEASE_CONTRACTS[name];
		const object = output.contracts[source]?.[name]?.evm.bytecode.object;
		if (!object)
			throw new Error(
				`${name} missing from the build output (expected in ${source})`,
			);
		codes[name] = hex(object);
	}
	return codes;
}

/**
 * The runtime record of `name`: solc's runtime object has every immutable still zero, so its hash
 * is the hash of the deployed code with those ranges zeroed, wherever and however it was deployed.
 */
function runtimeOf(
	output: BuildInfo["output"],
	name: ReleaseContract,
): ReleaseRuntime {
	const deployed =
		output.contracts[RELEASE_CONTRACTS[name]]?.[name]?.evm.deployedBytecode;
	if (!deployed?.object)
		throw new Error(`${name} has no runtime code in the build output`);
	const immutables = Object.values(deployed.immutableReferences ?? {})
		.flat()
		.map(({ start, length }) => ({ start, length }))
		.sort((a, b) => a.start - b.start);
	return { codehash: keccak256(hex(deployed.object)), immutables };
}

/** Compiles a frozen release's standard-JSON input with the solc it names. */
function compileRelease(
	version: string,
	release: Release,
): BuildInfo["output"] {
	const input = JSON.parse(
		fs.readFileSync(
			path.join(RELEASES_DIR, version, "standard-input.json"),
			"utf8",
		),
	) as StandardInput;
	const solc = solcFor(release.compiler.solc);
	const reported = execFileSync(solc, ["--version"]).toString();
	if (!reported.includes(release.compiler.solc.replace(/^v/, "")))
		throw new Error(
			`${solc} is not solc ${release.compiler.solc}:\n${reported}`,
		);
	// solc resolves nothing from disk here: every source is inlined in the input.
	const output = JSON.parse(
		execFileSync(solc, ["--standard-json"], {
			input: JSON.stringify({
				...input,
				settings: { ...input.settings, outputSelection: VERIFY_SELECTION },
			}),
			maxBuffer: 1 << 30,
			cwd: os.tmpdir(),
		}).toString(),
	);
	const errors = (output.errors ?? []).filter(
		(e: { severity: string }) => e.severity === "error",
	);
	if (errors.length)
		throw new Error(
			`${version}: solc reported errors:\n${errors.map((e: { formattedMessage: string }) => e.formattedMessage).join("\n")}`,
		);
	return output;
}

/** Writes release.json, keeping a committed file's layout (v2's is one line) so a diff shows only what changed. */
function writeRelease(version: string, release: Release): void {
	const file = path.join(RELEASES_DIR, version, "release.json");
	const oneLine =
		fs.existsSync(file) &&
		fs.readFileSync(file, "utf8").trimEnd().split("\n").length === 1;
	fs.writeFileSync(
		file,
		`${oneLine ? JSON.stringify(release) : JSON.stringify(release, null, 2)}\n`,
	);
}

function cut(version: string | undefined): void {
	if (!version || !/^v\d+$/.test(version))
		throw new Error("usage: pnpm release:cut v<N>");
	const dir = path.join(RELEASES_DIR, version);
	if (fs.existsSync(dir))
		throw new Error(
			`${version} already exists — releases are immutable; cut the next version instead`,
		);
	const existing = listReleases();
	const expected = `v${existing.length === 0 ? 1 : Number(existing[existing.length - 1].slice(1)) + 1}`;
	if (version !== expected)
		throw new Error(`the next release is ${expected}, not ${version}`);

	const build = foundryBuild();
	const codes = creationCodes(build.output);
	const { outputSelection: _ignored, ...settings } = build.input.settings;
	const release: Release = {
		version,
		compiler: { solc: build.solcLongVersion, settings },
		contracts: Object.fromEntries(
			(Object.keys(RELEASE_CONTRACTS) as ReleaseContract[]).map((name) => [
				name,
				{ source: RELEASE_CONTRACTS[name], creationCode: codes[name] },
			]),
		) as Release["contracts"],
	};
	fs.mkdirSync(dir, { recursive: true });
	fs.writeFileSync(
		path.join(dir, "release.json"),
		`${JSON.stringify(release, null, 2)}\n`,
	);
	// Standard JSON only. Forge's build-info adds its own CLI options (allowPaths, basePath, …) with
	// absolute paths from the machine that cut the release; solc needs none of them, since every
	// source is inlined.
	const input: StandardInput = {
		language: build.input.language,
		sources: build.input.sources,
		settings: { ...build.input.settings, outputSelection: OUTPUT_SELECTION },
	};
	fs.writeFileSync(
		path.join(dir, "standard-input.json"),
		`${JSON.stringify(input)}\n`,
	);
	// The runtime record comes from the frozen input, as `verify` recomputes it.
	const output = compileRelease(version, release);
	for (const name of RUNTIME_CONTRACTS)
		release.contracts[name].runtime = runtimeOf(output, name);
	writeRelease(version, release);
	console.log(
		`Cut ${version}: ${Object.keys(codes).join(", ")} (solc ${build.solcLongVersion})`,
	);
}

function solcFor(longVersion: string): string {
	if (process.env.SOLC) return process.env.SOLC;
	const short = longVersion.split("+")[0];
	// Where Foundry's svm keeps compilers: ~/.svm if it exists, otherwise the OS data directory.
	const roots = [
		path.join(os.homedir(), ".svm"),
		path.join(
			process.env.XDG_DATA_HOME ?? path.join(os.homedir(), ".local", "share"),
			"svm",
		),
		path.join(os.homedir(), "Library", "Application Support", "svm"),
	];
	const candidates = roots.map((root) =>
		path.join(root, short, `solc-${short}`),
	);
	const bin = candidates.find((candidate) => fs.existsSync(candidate));
	if (!bin)
		throw new Error(
			`solc ${short} not found (looked in ${candidates.join(", ")}); run \`forge build\` once, or set SOLC`,
		);
	return bin;
}

function verify(): void {
	const versions = listReleases();
	if (versions.length === 0) throw new Error("no releases to verify");
	for (const version of versions) {
		const release = loadRelease(version);
		const output = compileRelease(version, release);
		const names = Object.keys(release.contracts) as ReleaseContract[];
		const codes = creationCodes(output, names);
		for (const name of names) {
			if (
				codes[name].toLowerCase() !==
				release.contracts[name].creationCode.toLowerCase()
			) {
				throw new Error(
					`${version}: ${name} does not reproduce from standard-input.json — the release is corrupt`,
				);
			}
		}
		for (const name of RUNTIME_CONTRACTS) {
			const recorded = release.contracts[name].runtime;
			if (!recorded)
				throw new Error(
					`${version}: ${name} has no runtime record; run \`pnpm release:runtime\``,
				);
			if (JSON.stringify(recorded) !== JSON.stringify(runtimeOf(output, name)))
				throw new Error(
					`${version}: ${name}'s runtime record does not reproduce from standard-input.json`,
				);
		}
		console.log(
			`OK ${version}: every contract reproduces from its standard-JSON input with solc ${release.compiler.solc}`,
		);
	}
}

/**
 * Records the runtime of RUNTIME_CONTRACTS in each release that predates the record (D13). It is
 * derived from the frozen input, which stays as it was, so the release deploys exactly what it did;
 * a record already there is left alone, and `verify` checks it.
 */
function runtime(): void {
	for (const version of listReleases()) {
		const release = loadRelease(version);
		const missing = RUNTIME_CONTRACTS.filter(
			(name) => !release.contracts[name].runtime,
		);
		if (missing.length === 0) continue;
		const output = compileRelease(version, release);
		for (const name of missing)
			release.contracts[name].runtime = runtimeOf(output, name);
		writeRelease(version, release);
		console.log(`Recorded ${version}: ${missing.join(", ")}`);
	}
}

function status(): void {
	const version = latestRelease();
	const release = loadRelease(version);
	const codes = creationCodes(foundryBuild().output);
	const changed = (Object.keys(RELEASE_CONTRACTS) as ReleaseContract[]).filter(
		(name) =>
			codes[name].toLowerCase() !==
			release.contracts[name].creationCode.toLowerCase(),
	);
	if (changed.length === 0) console.log(`The build matches ${version}.`);
	else
		console.log(
			`Unreleased changes since ${version}: ${changed.join(", ")}. Cut the next release before deploying them.`,
		);
}

const [command, arg] = process.argv.slice(2);
if (command === "cut") cut(arg);
else if (command === "verify") verify();
else if (command === "runtime") runtime();
else if (command === "status") status();
else {
	console.error("usage: release.ts cut <version> | verify | runtime | status");
	process.exit(2);
}
