/**
 * Step 5 of the Cut-over runbook (TESTNET-ROLLOUT.md): points dev's `chains` secret at release v3.
 *
 * The secret's source of truth is the 1Password note `secrets-dev` (vault "Giano dev/stg"). Its
 * `notesPlain` is the whole secret bundle, `{ "<name>": { "value": "<string>", "version": n }, … }`,
 * and Terraform (infra/iac/asm.tf) reads each secret's value and version from it; the version is the
 * only signal that a value changed. So this takes the bundle on stdin, rewrites the Base Sepolia and
 * Ethereum Sepolia entries inside `chains.value` (a JSON document in a string), bumps
 * `chains.version`, and writes the whole bundle to stdout, to paste back into the note as-is:
 *
 *   op item get secrets-dev --vault "Giano dev/stg" --format json \
 *     | jq -r '.fields[] | select(.id == "notesPlain") | .value' \
 *     | (cd packages/contracts && node --import tsx ../../deploy/contracts/dev-v3-chains.mts) | pbcopy
 *
 * (tsx lives in packages/contracts, where the deploy tooling runs.)
 *
 * Every address and the timelock delays come from the committed deployment records
 * (packages/contracts/deployments/<chainId>.json) and profiles, never retyped. Every other field
 * (rpcUrl, other policy limits, bundler and console settings, other chains) is kept. Each rewritten
 * entry is checked against wallet-api's and the bundler's chain schemas, and the list against
 * validateChainList, before anything is printed. What changed is listed on stderr, without the RPC
 * URLs. Nothing is written anywhere.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
	bundlerChainSchema,
	validateChainList,
	walletApiChainSchema,
} from "../../packages/contracts/chains";
import { ENTRY_POINT_V09 } from "../../packages/contracts/deploy/config";
import {
	loadProfile,
	REPO_ROOT,
} from "../../packages/contracts/deploy/profiles";

const CHAINS = [
	{ chainId: 84532, profile: "base-sepolia" },
	{ chainId: 11155111, profile: "ethereum-sepolia" },
] as const;

export type Entry = Record<string, unknown> & {
	chainId?: number;
	walletApi?: Record<string, unknown> & { policy?: Record<string, unknown> };
	paymasterAdmin?: Record<string, unknown>;
};

/**
 * The relay's paymaster allowlist lives in wallet-api's database (seeded with the chain's
 * sponsorshipPaymaster, edited in the console), so the chain document no longer overrides it. An
 * existing override is removed; any other policy field is kept.
 */
export function dropPaymasterOverride(entry: Entry): void {
	const policy = entry.walletApi?.policy;
	if (!entry.walletApi || !policy || !("allowedPaymasters" in policy)) return;
	const { allowedPaymasters: _dropped, ...rest } = policy;
	if (Object.keys(rest).length > 0) entry.walletApi.policy = rest;
	else delete entry.walletApi.policy;
}

export function v3For(chainId: number, profileId: string) {
	const record = JSON.parse(
		readFileSync(
			join(REPO_ROOT, "packages/contracts/deployments", `${chainId}.json`),
			"utf8",
		),
	);
	const { profile } = loadProfile({ chain: profileId });
	const proxy = record.contracts?.paymasterProxy?.address;
	const factory = record.contracts?.factory?.address;
	const implementation = record.contracts?.walletImplementation?.address;
	const timelock = record.timelock?.address;
	if (!proxy || !factory || !implementation || !timelock)
		throw new Error(
			`deployments/${chainId}.json lacks a v3 contract or the timelock`,
		);
	if (!profile.timelock || profile.timelock.address !== timelock)
		throw new Error(
			`${profileId}'s timelock.address is not the recorded timelock ${timelock}`,
		);
	return {
		proxy,
		factory,
		implementation,
		timelock,
		delays: profile.timelock.delays,
	};
}

export function pointAtV3(bundle: Record<string, unknown>): {
	bundle: Record<string, unknown>;
	notes: string[];
} {
	const chains = bundle.chains as
		| { value?: unknown; version?: unknown }
		| undefined;
	if (
		!chains ||
		typeof chains.value !== "string" ||
		typeof chains.version !== "number"
	)
		throw new Error(
			'the bundle has no "chains": { "value": "<json>", "version": <number> } entry',
		);
	const document = JSON.parse(chains.value) as Entry[];
	if (!Array.isArray(document))
		throw new Error("chains.value is not a JSON array");

	const notes: string[] = [];
	let changed = false;
	for (const { chainId, profile } of CHAINS) {
		const entry = document.find((e) => e.chainId === chainId);
		if (!entry)
			throw new Error(`chains.value has no entry for chain ${chainId}`);
		const v3 = v3For(chainId, profile);
		const before = JSON.stringify({ ...entry, rpcUrl: undefined });
		entry.entryPoint = ENTRY_POINT_V09;
		entry.sponsorshipPaymaster = v3.proxy;
		entry.walletApi = {
			...entry.walletApi,
			factory: v3.factory,
			...(entry.walletApi?.implementation
				? { implementation: v3.implementation }
				: {}),
		};
		dropPaymasterOverride(entry);
		entry.paymasterAdmin = {
			...entry.paymasterAdmin,
			timelockAddress: v3.timelock,
			timelockDelays: v3.delays,
		};
		for (const schema of [walletApiChainSchema, bundlerChainSchema]) {
			const parsed = schema.safeParse(entry);
			if (!parsed.success)
				throw new Error(
					`chain ${chainId} fails a chain schema: ${parsed.error.message}`,
				);
		}
		const same = before === JSON.stringify({ ...entry, rpcUrl: undefined });
		if (!same) changed = true;
		notes.push(
			`chain ${chainId}: ${same ? "already v3" : "set to v3"} (paymaster ${v3.proxy}, factory ${v3.factory}, timelock ${v3.timelock})`,
		);
	}
	const { errors, warnings } = validateChainList(
		document.map((e) => walletApiChainSchema.parse(e)),
	);
	if (errors.length)
		throw new Error(`the chain list is invalid: ${errors.join("; ")}`);
	notes.push(...warnings.map((w) => `warning: ${w}`));
	if (!changed) {
		notes.push(`nothing to change: chains.version stays ${chains.version}`);
		return { bundle, notes };
	}
	notes.push(`chains.version ${chains.version} → ${chains.version + 1}`);
	return {
		bundle: {
			...bundle,
			chains: {
				...chains,
				value: JSON.stringify(document),
				version: chains.version + 1,
			},
		},
		notes,
	};
}

if (process.argv[1] && /dev-v3-chains\.mts$/.test(process.argv[1])) {
	try {
		const { bundle, notes } = pointAtV3(JSON.parse(readFileSync(0, "utf8")));
		for (const note of notes) console.error(note);
		process.stdout.write(`${JSON.stringify(bundle, null, 2)}\n`);
	} catch (error) {
		console.error(`FAILED: ${(error as Error).message}`);
		process.exit(1);
	}
}
