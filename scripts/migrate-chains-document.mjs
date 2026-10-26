#!/usr/bin/env node
// Rewrites a flat backend chain document — `chains` as wallet-api and paymaster-admin read it before
// per-service sections (packages/contracts/chains.ts) — into the sectioned shape. One-shot. Reads
// stdin, writes stdout, explains to stderr.
//
// The source of truth is the 1Password note (specs/INFRASTRUCTURE.md §12), never Secrets Manager: a
// value reaches ASM only through `terraform apply`, and only when its `version` moves. So the usual
// input is the whole note, with --bundle: `chains.value` (a JSON document inside a string) is
// converted in place and `chains.version` bumped, every other entry left as it was. Paste the output
// back into the note as-is — no hand-escaping.
//
//   op item get secrets-dev --vault "Giano dev/stg" --format json \
//     | jq -r '.fields[] | select(.id == "notesPlain") | .value' \
//     | node scripts/migrate-chains-document.mjs --bundle
//
// Without --bundle the input is the chain document itself.
//
// `bundlerUrl` is dropped: wallet-api now derives it from BUNDLER_BASE_URL. A chain that really is
// submitted through another bundler needs `walletApi.bundlerUrl` and `bundler.enabled: false` put
// back by hand — the script lists every URL it drops, so nothing disappears silently. A field it does
// not recognise stops it rather than being guessed at.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const SHARED = [
	"chainId",
	"name",
	"rpcUrl",
	"nativeCurrency",
	"entryPoint",
	"sponsorshipPaymaster",
];
const SECTIONS = {
	walletApi: ["factory", "policy"],
	paymasterAdmin: ["walletRpcUrl", "refreshSeconds"],
};
const DROPPED = ["bundlerUrl"];

/** @returns {{ document: object[], notes: string[] }} */
export function migrate(input) {
	if (!Array.isArray(input))
		throw new Error("the chain document must be a JSON array");
	const notes = [];
	const document = input.map((entry, index) => {
		const label = `entry ${index} (chain ${entry?.chainId ?? "?"})`;
		if (!entry || typeof entry !== "object" || Array.isArray(entry))
			throw new Error(`${label} is not an object`);
		if (
			Object.keys(SECTIONS).some((section) => section in entry) ||
			"bundler" in entry
		) {
			throw new Error(
				`${label} already has per-service sections — nothing to migrate`,
			);
		}
		const out = {};
		const sections = {};
		for (const [key, value] of Object.entries(entry)) {
			if (SHARED.includes(key)) {
				out[key] = value;
			} else if (DROPPED.includes(key)) {
				notes.push(
					`${label}: dropped ${key} ${JSON.stringify(value)} — wallet-api derives it from BUNDLER_BASE_URL now`,
				);
			} else {
				const section = Object.keys(SECTIONS).find((name) =>
					SECTIONS[name].includes(key),
				);
				if (!section)
					throw new Error(
						`${label}: unrecognised field "${key}" — move it by hand`,
					);
				sections[section] = { ...sections[section], [key]: value };
			}
		}
		return { ...out, ...sections };
	});
	return { document, notes };
}

/**
 * The whole 1Password secret bundle: `{ "<name>": { "value": "…", "version": n }, … }`. Converts
 * `chains.value` and bumps `chains.version` — the bump is what makes `terraform apply` write the new
 * value to Secrets Manager (`secret_string_wo_version`).
 * @returns {{ bundle: object, notes: string[] }}
 */
export function migrateBundle(bundle) {
	if (!bundle || typeof bundle !== "object" || Array.isArray(bundle))
		throw new Error("the secret bundle must be a JSON object");
	const chains = bundle.chains;
	if (
		!chains ||
		typeof chains.value !== "string" ||
		typeof chains.version !== "number"
	) {
		throw new Error(
			'the bundle has no "chains": { "value": "<json>", "version": <number> } entry',
		);
	}
	let document;
	try {
		document = JSON.parse(chains.value);
	} catch (error) {
		throw new Error(`chains.value is not valid JSON: ${error.message}`);
	}
	const { document: migrated, notes } = migrate(document);
	notes.push(`chains.version ${chains.version} → ${chains.version + 1}`);
	return {
		bundle: {
			...bundle,
			chains: {
				...chains,
				value: JSON.stringify(migrated),
				version: chains.version + 1,
			},
		},
		notes,
	};
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
	try {
		const input = JSON.parse(readFileSync(0, "utf8"));
		if (process.argv.includes("--bundle")) {
			const { bundle, notes } = migrateBundle(input);
			for (const note of notes) console.error(note);
			process.stdout.write(`${JSON.stringify(bundle, null, 2)}\n`);
		} else {
			const { document, notes } = migrate(input);
			for (const note of notes) console.error(note);
			process.stdout.write(`${JSON.stringify(document, null, 2)}\n`);
		}
	} catch (error) {
		console.error(`FATAL: ${error.message}`);
		process.exit(1);
	}
}
