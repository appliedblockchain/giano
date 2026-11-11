/**
 * Each grant has its own storage key. `grant` and `revoke` each make one write to their own
 * origin's key and read nothing first. A shared list would need a read, a change and a write, and
 * two popups doing that at once could save a stale list and restore a revoked grant.
 */
const GRANT_KEY_PREFIX = "giano:connection-grant:";

const grantKey = (dappOrigin: string) => `${GRANT_KEY_PREFIX}${dappOrigin}`;

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
	/**
	 * Records the origin's grant. Throws when the storage refuses the write: a grant kept only in
	 * this popup's memory would outlive a revoke made in another popup.
	 */
	grant: (dappOrigin: string) => void;
	/**
	 * Removes the origin's grant. Throws when the storage refuses the write: the saved grant
	 * would otherwise let the next popup accept the origin again.
	 */
	revoke: (dappOrigin: string) => void;
};

type GrantStorage = Pick<Storage, "getItem" | "setItem" | "removeItem">;

/**
 * The wallet origin's `localStorage`, or `null` where the environment has none. The `in` check
 * does not run the property getter. The wrapper reads the property on every call, because the
 * getter throws when site data is blocked. Each method must see that error: a revoke must fail
 * instead of reporting success while a saved grant stays on disk.
 */
function defaultStorage(): GrantStorage | null {
	if (!("localStorage" in globalThis)) return null;
	return {
		getItem: (key) => globalThis.localStorage.getItem(key),
		setItem: (key, value) => globalThis.localStorage.setItem(key, value),
		removeItem: (key) => globalThis.localStorage.removeItem(key),
	};
}

/**
 * Grants backed by `storage` (the wallet origin's `localStorage` by default). The storage is the
 * only place a grant lives, so a revoke in any popup ends it in every popup: `has` reads the
 * storage on each call. When the storage refuses a grant, `grant` throws and nothing is granted.
 * Pass `null` for no storage: the grants then live in this popup's memory, which no other popup
 * shares.
 */
export function createConnectionGrants(
	storage: GrantStorage | null = defaultStorage(),
): ConnectionGrants {
	// With no storage, this popup's grants. With storage, only `false`, for an origin whose revoke
	// the storage refused: the storage still holds that grant, and this popup must not honour it.
	const local = new Map<string, boolean>();

	const saved = (dappOrigin: string): boolean => {
		if (!storage) return false;
		try {
			return storage.getItem(grantKey(dappOrigin)) !== null;
		} catch {
			// Unreadable storage grants nothing.
			return false;
		}
	};

	return {
		has: (dappOrigin) => local.get(dappOrigin) ?? saved(dappOrigin),
		grant: (dappOrigin) => {
			if (!storage) {
				local.set(dappOrigin, true);
				return;
			}
			// A refused write throws to the caller and grants nothing.
			storage.setItem(grantKey(dappOrigin), new Date().toISOString());
			local.delete(dappOrigin);
		},
		revoke: (dappOrigin) => {
			if (!storage) {
				local.delete(dappOrigin);
				return;
			}
			try {
				storage.removeItem(grantKey(dappOrigin));
				local.delete(dappOrigin);
			} catch (error) {
				// This popup stops serving the origin; the caller must report the failure.
				local.set(dappOrigin, false);
				throw error;
			}
		},
	};
}
