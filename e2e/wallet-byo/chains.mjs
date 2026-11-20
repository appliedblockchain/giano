// The chains the BYO wallet serves: ids and names only, because every endpoint is wallet-api's.
// serve.mjs calls resolveChains() once at start-up and bakes the result into the SPA.
//
// Two forms, never both:
//
//   CHAINS                        a JSON array of { chainId, name }, e.g.
//                                 [{"chainId":84532,"name":"Base Sepolia"}]
//   CHAIN_ID, CHAIN_NAME,         the older pair, kept because infra/iac still sets it. It
//   CHAIN_B_ID, CHAIN_B_NAME      keeps the defaults serve.mjs had before CHAINS existed:
//                                 CHAIN_ID is required; the second chain falls away when
//                                 CHAIN_B_ID is unset, empty or 0; a missing name is
//                                 "chain <id>". Spaces and newlines around an id are ignored.
//
// The pair's ids are checked more strictly than before. serve.mjs passed them to Number(), so it
// took any value Number() reads, such as hex. An id must now be a decimal positive integer. A
// CHAIN_B_ID such as "00" or "-1" used to drop the second chain without a word. Now it stops the
// service at start-up.
//
// In a devnet checkout (../devnet/addresses.json present) and with no chain variable set, the
// list is every local chain: Devnet A (the devnet's chainId, 31337), Devnet B (31338) and
// Devnet SD (Silent Data) (31339). With only some of the pair's variables set, the pair applies,
// with the devnet's ids and names for the ones left unset, as before CHAINS existed.
//
// Every list, from either form, is checked: it is not empty, every id is a positive integer,
// no id repeats, and no name is empty. CHAINS replaces all four variables of the pair. Setting
// CHAINS together with any of them is refused, even CHAIN_B_ID=0, because that value would be
// ignored without a word.

/** A refusal. serve.mjs prints the message and exits non-zero before it serves anything. */
export class ChainsConfigError extends Error {
	name = "ChainsConfigError";
}

const isSet = (value) => value !== undefined && value !== "";

/**
 * The pair's variables. CHAINS replaces all four. Any of them, even set to "", selects the pair
 * over the devnet default.
 */
const PAIR_VARIABLES = ["CHAIN_ID", "CHAIN_NAME", "CHAIN_B_ID", "CHAIN_B_NAME"];

/** Every chain the local stacks run, in a devnet checkout with no chain variable set. */
function devnetChains(devnet) {
	return [
		{ chainId: devnet.chainId ?? 31337, name: "Devnet A" },
		{ chainId: 31338, name: "Devnet B" },
		{ chainId: 31339, name: "Devnet SD (Silent Data)" },
	];
}

/** The id as a number, or NaN when it is not a positive integer. Env values are strings. */
function parseId(value) {
	const id =
		typeof value === "number"
			? value
			: typeof value === "string" && /^[0-9]+$/.test(value)
				? Number(value)
				: Number.NaN;
	return Number.isSafeInteger(id) && id > 0 ? id : Number.NaN;
}

function fromChainsVariable(raw) {
	let parsed;
	try {
		parsed = JSON.parse(raw);
	} catch (error) {
		throw new ChainsConfigError(
			`CHAINS is not valid JSON (${error.message}). Set it to a JSON array of { chainId, name }.`,
		);
	}
	if (!Array.isArray(parsed)) {
		throw new ChainsConfigError(
			"CHAINS must be a JSON array of { chainId, name }.",
		);
	}
	return parsed.map((entry, index) => {
		const where = `CHAINS[${index}]`;
		if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
			throw new ChainsConfigError(
				`${where} must be an object { chainId, name }.`,
			);
		}
		if (typeof entry.chainId !== "number") {
			throw new ChainsConfigError(
				`${where}.chainId must be a positive integer, got ${JSON.stringify(entry.chainId)}.`,
			);
		}
		if (typeof entry.name !== "string") {
			throw new ChainsConfigError(
				`${where}.name must be a non-empty string, got ${JSON.stringify(entry.name)}.`,
			);
		}
		return {
			chainId: entry.chainId,
			name: entry.name,
			idLabel: `${where}.chainId`,
			nameLabel: `${where}.name`,
		};
	});
}

/** An env value without the spaces or newline around it, which an env file or a secret can add. */
const trimmed = (value) => (typeof value === "string" ? value.trim() : value);

function fromPair(env, devnet) {
	const rawId = trimmed(env.CHAIN_ID) ?? devnet?.chainId;
	if (rawId === undefined || rawId === null || rawId === "") {
		throw new ChainsConfigError(
			"CHAIN_ID is required — the chain this wallet origin serves, e.g. 84532 " +
				"(or set CHAINS, a JSON array of { chainId, name })\n" +
				"       (it defaults only in an e2e checkout, from ../devnet/addresses.json)",
		);
	}
	const rawBId = trimmed(env.CHAIN_B_ID) ?? (devnet ? "31338" : "");
	const chains = [
		{
			chainId: parseId(rawId),
			name: env.CHAIN_NAME ?? (devnet ? "Devnet A" : `chain ${rawId}`),
			idLabel: "CHAIN_ID",
			nameLabel: "CHAIN_NAME",
			raw: rawId,
		},
	];
	// "0" falls away too: the SPA used to read CHAIN_B_ID as Number(CHAIN_B_ID || "0") > 0.
	if (rawBId !== "" && rawBId !== "0") {
		chains.push({
			chainId: parseId(rawBId),
			name: env.CHAIN_B_NAME ?? (devnet ? "Devnet B" : `chain ${rawBId}`),
			idLabel: "CHAIN_B_ID",
			nameLabel: "CHAIN_B_NAME",
			raw: rawBId,
		});
	}
	return chains;
}

/**
 * The chain list from the environment.
 *
 * @param {Record<string, string | undefined>} env usually process.env
 * @param {{ chainId?: number } | null} devnet ../devnet/addresses.json, or null outside a checkout
 * @returns {{ chainId: number, name: string }[]}
 * @throws {ChainsConfigError} when the configuration is refused
 */
export function resolveChains(env, devnet = null) {
	let chains;
	if (isSet(env.CHAINS)) {
		const pair = PAIR_VARIABLES.filter((name) => isSet(env[name]));
		if (pair.length > 0) {
			throw new ChainsConfigError(
				`CHAINS is set together with ${pair.join(", ")}. CHAINS replaces ${PAIR_VARIABLES.join(", ")}. Unset them, or unset CHAINS.`,
			);
		}
		chains = fromChainsVariable(env.CHAINS);
		if (chains.length === 0) {
			throw new ChainsConfigError(
				"CHAINS is an empty list. It must name at least one chain.",
			);
		}
	} else if (
		devnet &&
		PAIR_VARIABLES.every((name) => env[name] === undefined)
	) {
		return devnetChains(devnet);
	} else {
		chains = fromPair(env, devnet);
	}

	const seen = new Set();
	for (const chain of chains) {
		if (Number.isNaN(parseId(chain.chainId))) {
			throw new ChainsConfigError(
				`${chain.idLabel} must be a positive integer, got ${JSON.stringify(chain.raw ?? chain.chainId)}.`,
			);
		}
		if (seen.has(chain.chainId)) {
			throw new ChainsConfigError(
				`Chain ${chain.chainId} appears twice (${chain.idLabel}). Each chain id must be unique.`,
			);
		}
		seen.add(chain.chainId);
		if (chain.name.trim() === "") {
			throw new ChainsConfigError(
				`${chain.nameLabel} is empty. Each chain needs a name: the consent screens show it.`,
			);
		}
	}
	return chains.map(({ chainId, name }) => ({ chainId, name }));
}
