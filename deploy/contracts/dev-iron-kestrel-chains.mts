/**
 * Adds Silent Data's iron-kestrel (19874) to dev's `chains` secret (TESTNET-ROLLOUT.md, "Adding
 * iron-kestrel to dev").
 *
 * Same input and output as dev-v3-chains.mts: the 1Password `secrets-dev` bundle on stdin, the
 * whole bundle on stdout, to paste back into the note as-is. It adds the 19874 entry, or updates it
 * when it is already there, and bumps `chains.version` when anything changed:
 *
 *   read -rs IRON_KESTREL_RPC_URL && export IRON_KESTREL_RPC_URL   # paste the write URL; not echoed
 *   op item get secrets-dev --vault "Giano dev/stg" --format json \
 *     | jq -r '.fields[] | select(.id == "notesPlain") | .value' \
 *     | (cd packages/contracts && node --import tsx ../../deploy/contracts/dev-iron-kestrel-chains.mts) | pbcopy
 *
 * The addresses and the timelock delays come from the committed record
 * (packages/contracts/deployments/19874.json) and the profile (deploy/chains/iron-kestrel.json),
 * never retyped. `rpcUrl` is the profile's public URL, which wallet-api reads through. The bundler
 * sends transactions, which Silent Data accepts only with a token, so `bundler.rpcUrl` is the write
 * URL that holds the token. It comes from IRON_KESTREL_RPC_URL (the profile's `rpcUrlEnv`) in the
 * environment, never from an argument or a file in git. `bundler.stateOverride` is false: the
 * gateway refuses eth_call state overrides (openspec silent-data-network, design §2).
 *
 * Any other field of an existing 19874 entry, and every other chain, is kept. The entry is checked
 * against wallet-api's and the bundler's chain schemas, and the list against validateChainList,
 * before anything is printed. What changed is listed on stderr, without the RPC URLs. Nothing is
 * written anywhere.
 */
import { readFileSync } from "node:fs";
import {
	bundlerChainSchema,
	validateChainList,
	walletApiChainSchema,
} from "../../packages/contracts/chains";
import { ENTRY_POINT_V09 } from "../../packages/contracts/deploy/config";
import { loadProfile } from "../../packages/contracts/deploy/profiles";
import { v3For } from "./dev-v3-chains.mts";

const CHAIN_ID = 19874;
const PROFILE = "iron-kestrel";

type Entry = Record<string, unknown> & {
	chainId?: number;
	walletApi?: Record<string, unknown> & { policy?: Record<string, unknown> };
	bundler?: Record<string, unknown>;
	paymasterAdmin?: Record<string, unknown>;
};

export function addIronKestrel(
	bundle: Record<string, unknown>,
	writeUrl: string | undefined,
): { bundle: Record<string, unknown>; notes: string[] } {
	const { profile } = loadProfile({ chain: PROFILE });
	if (profile.chainId !== CHAIN_ID)
		throw new Error(`deploy/chains/${PROFILE}.json is not chain ${CHAIN_ID}`);
	if (!writeUrl)
		throw new Error(
			`set ${profile.rpcUrlEnv} to iron-kestrel's write URL (the one with the token)`,
		);
	let parsedUrl: URL;
	try {
		parsedUrl = new URL(writeUrl);
	} catch {
		throw new Error(`${profile.rpcUrlEnv} is not a URL`);
	}
	if (parsedUrl.protocol !== "https:")
		throw new Error(`${profile.rpcUrlEnv} is not an https URL`);
	// Compare what the server receives: URL parsing lowercases the host and drops a default port,
	// and the fragment is never sent, so `https://IRON-KESTREL.silentdata.com:443/#x` is the public URL too.
	const endpoint = (u: URL) =>
		`${u.origin}${u.pathname.replace(/\/+$/, "")}${u.search}`;
	if (endpoint(parsedUrl) === endpoint(new URL(profile.rpcUrl)))
		throw new Error(
			`${profile.rpcUrlEnv} is the public URL; the bundler needs the write URL with the token`,
		);

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
	const before = JSON.stringify(document);

	const v3 = v3For(CHAIN_ID, PROFILE);
	const existing = document.find((e) => e.chainId === CHAIN_ID);
	const entry: Entry = existing ?? { chainId: CHAIN_ID };
	entry.name = profile.name;
	entry.rpcUrl = profile.rpcUrl;
	entry.entryPoint = ENTRY_POINT_V09;
	entry.sponsorshipPaymaster = v3.proxy;
	entry.walletApi = {
		...entry.walletApi,
		factory: v3.factory,
		policy: { ...entry.walletApi?.policy, allowedPaymasters: [v3.proxy] },
	};
	entry.bundler = { ...entry.bundler, rpcUrl: writeUrl, stateOverride: false };
	entry.paymasterAdmin = {
		...entry.paymasterAdmin,
		timelockAddress: v3.timelock,
		timelockDelays: v3.delays,
	};
	if (!existing) document.push(entry);

	for (const schema of [walletApiChainSchema, bundlerChainSchema]) {
		const parsed = schema.safeParse(entry);
		if (!parsed.success)
			throw new Error(
				`chain ${CHAIN_ID} fails a chain schema: ${parsed.error.message}`,
			);
	}
	const { errors, warnings } = validateChainList(
		document.map((e) => walletApiChainSchema.parse(e)),
	);
	if (errors.length)
		throw new Error(`the chain list is invalid: ${errors.join("; ")}`);

	const same = JSON.stringify(document) === before;
	const notes = [
		`chain ${CHAIN_ID}: ${same ? "already set" : existing ? "updated" : "added"} (paymaster ${v3.proxy}, factory ${v3.factory}, timelock ${v3.timelock}, bundler.stateOverride false)`,
		...warnings.map((w) => `warning: ${w}`),
	];
	if (same) {
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

if (process.argv[1] && /dev-iron-kestrel-chains\.mts$/.test(process.argv[1])) {
	try {
		const { profile } = loadProfile({ chain: PROFILE });
		const { bundle, notes } = addIronKestrel(
			JSON.parse(readFileSync(0, "utf8")),
			process.env[profile.rpcUrlEnv],
		);
		for (const note of notes) console.error(note);
		process.stdout.write(`${JSON.stringify(bundle, null, 2)}\n`);
	} catch (error) {
		console.error(`FAILED: ${(error as Error).message}`);
		process.exit(1);
	}
}
