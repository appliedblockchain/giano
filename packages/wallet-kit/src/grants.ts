const GRANTS_KEY = "giano:connection-grants";

/**
 * The dApp origins the user has connected to this wallet (WK-34).
 *
 * A grant is recorded when the user approves `eth_requestAccounts` for an origin. Without one, an
 * origin cannot read the account or reach any method that uses it. The popup is ephemeral, so the
 * grants are kept in the wallet origin's storage, not in memory: each request after the connect
 * arrives in a fresh popup and must still find the grant.
 */
export type ConnectionGrants = {
	has: (dappOrigin: string) => boolean;
	grant: (dappOrigin: string) => void;
	revoke: (dappOrigin: string) => void;
};

type GrantStorage = Pick<Storage, "getItem" | "setItem">;

function defaultStorage(): GrantStorage | undefined {
	try {
		return typeof localStorage === "undefined" ? undefined : localStorage;
	} catch {
		// Storage access can throw (blocked site data, sandboxed frame).
		return undefined;
	}
}

/**
 * Grants backed by `storage` (the wallet origin's `localStorage` by default). Without usable
 * storage the grants live in memory only, so they last as long as the popup does: the user is
 * asked to connect again, which is the safe direction to fail in. Pass `null` for no storage.
 */
export function createConnectionGrants(
	storage: GrantStorage | null = defaultStorage() ?? null,
): ConnectionGrants {
	let backing: GrantStorage | undefined = storage ?? undefined;
	let memory = new Set<string>();

	const read = (): Set<string> => {
		if (!backing) return new Set(memory);
		try {
			const parsed: unknown = JSON.parse(backing.getItem(GRANTS_KEY) ?? "[]");
			return new Set(
				Array.isArray(parsed)
					? parsed.filter((entry): entry is string => typeof entry === "string")
					: [],
			);
		} catch {
			// An unreadable entry grants nothing.
			return new Set();
		}
	};

	const write = (origins: Set<string>) => {
		memory = origins;
		if (!backing) return;
		try {
			backing.setItem(GRANTS_KEY, JSON.stringify([...origins]));
		} catch {
			// Storage refused the write: keep the grants in memory for the rest of this popup.
			backing = undefined;
		}
	};

	return {
		has: (dappOrigin) => read().has(dappOrigin),
		grant: (dappOrigin) => {
			const origins = read();
			origins.add(dappOrigin);
			write(origins);
		},
		revoke: (dappOrigin) => {
			const origins = read();
			origins.delete(dappOrigin);
			write(origins);
		},
	};
}
