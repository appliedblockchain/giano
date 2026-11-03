/**
 * Compiles a committed release from its standard-JSON input with plain solc (no Foundry, nothing
 * resolved from disk), returning per contract what verification needs: the creation code, the
 * runtime code and where its immutables sit.
 *
 * `release:verify` uses it to check that a release reproduces; `gen:releases` uses it to derive each
 * contract's code fingerprint (scripts/generate-releases.ts).
 *
 * The solc binary is $SOLC if set, otherwise the one Foundry's svm installs for the release's
 * version, which any `forge build` on this repo provides.
 */
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { Hex } from "viem";
import { loadRelease, RELEASES_DIR, type ReleaseContract } from "./release";

/** A run of bytes in the runtime code that solc fills with an immutable's value at deployment. */
export type ImmutableRange = { start: number; length: number };

/** One immutable variable and every place the runtime code embeds it. */
export type CompiledImmutable = {
	/** `<declaring contract>.<variable>`, e.g. `UUPSUpgradeable.__self`. */
	name: string;
	ranges: ImmutableRange[];
};

export type CompiledContract = {
	creationCode: Hex;
	/** The runtime code with every immutable still zero, as solc emits it. */
	runtimeCode: Hex;
	immutables: CompiledImmutable[];
};

type StandardInput = {
	language: string;
	sources: Record<string, unknown>;
	settings: Record<string, unknown>;
};

type AstNode = {
	id?: number;
	nodeType?: string;
	name?: string;
	scope?: number;
	[key: string]: unknown;
};

type SolcContractOutput = {
	evm: {
		bytecode: { object: string };
		deployedBytecode: {
			object: string;
			immutableReferences?: Record<string, ImmutableRange[]>;
		};
	};
};

type SolcOutput = {
	errors?: { severity: string; formattedMessage: string }[];
	sources: Record<string, { ast: AstNode }>;
	contracts: Record<string, Record<string, SolcContractOutput>>;
};

/** What we ask solc for. None of it changes the bytecode; only the selection differs from the release's own. */
const OUTPUT_SELECTION = {
	"*": {
		"*": [
			"evm.bytecode.object",
			"evm.deployedBytecode.object",
			"evm.deployedBytecode.immutableReferences",
		],
		"": ["ast"],
	},
};

function hex(object: string): Hex {
	return (object.startsWith("0x") ? object : `0x${object}`) as Hex;
}

/** The solc binary for a release's compiler version. */
export function solcFor(longVersion: string): string {
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

/** Every VariableDeclaration and ContractDefinition in the ASTs, by node id. */
function indexAst(sources: SolcOutput["sources"]): Map<number, AstNode> {
	const byId = new Map<number, AstNode>();
	const walk = (node: unknown): void => {
		if (Array.isArray(node)) {
			for (const child of node) walk(child);
			return;
		}
		if (!node || typeof node !== "object") return;
		const n = node as AstNode;
		if (
			typeof n.id === "number" &&
			(n.nodeType === "VariableDeclaration" ||
				n.nodeType === "ContractDefinition")
		)
			byId.set(n.id, n);
		for (const value of Object.values(n)) walk(value);
	};
	for (const { ast } of Object.values(sources)) walk(ast);
	return byId;
}

function immutableName(byId: Map<number, AstNode>, id: number): string {
	const variable = byId.get(id);
	if (!variable?.name)
		throw new Error(`immutable reference ${id} has no declaration in the AST`);
	const owner =
		variable.scope === undefined ? undefined : byId.get(variable.scope);
	return `${owner?.name ?? "?"}.${variable.name}`;
}

/**
 * Compiles release `version` from releases/<version>/standard-input.json and returns every contract
 * the release carries.
 */
export function compileRelease(
	version: string,
): Partial<Record<ReleaseContract, CompiledContract>> {
	const release = loadRelease(version);
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
				settings: { ...input.settings, outputSelection: OUTPUT_SELECTION },
			}),
			maxBuffer: 1 << 30,
			cwd: os.tmpdir(),
		}).toString(),
	) as SolcOutput;
	const errors = (output.errors ?? []).filter((e) => e.severity === "error");
	if (errors.length)
		throw new Error(
			`${version}: solc reported errors:\n${errors.map((e) => e.formattedMessage).join("\n")}`,
		);

	const byId = indexAst(output.sources);
	const compiled: Partial<Record<ReleaseContract, CompiledContract>> = {};
	for (const [name, { source }] of Object.entries(release.contracts) as [
		ReleaseContract,
		{ source: string },
	][]) {
		const evm = output.contracts[source]?.[name]?.evm;
		if (!evm)
			throw new Error(
				`${version}: ${name} missing from the solc output (expected in ${source})`,
			);
		const immutables = Object.entries(
			evm.deployedBytecode.immutableReferences ?? {},
		)
			.map(([id, ranges]) => ({
				name: immutableName(byId, Number(id)),
				ranges: ranges
					.map(({ start, length }) => ({ start, length }))
					.sort((a, b) => a.start - b.start),
			}))
			.sort((a, b) => a.name.localeCompare(b.name));
		compiled[name] = {
			creationCode: hex(evm.bytecode.object),
			runtimeCode: hex(evm.deployedBytecode.object),
			immutables,
		};
	}
	return compiled;
}
