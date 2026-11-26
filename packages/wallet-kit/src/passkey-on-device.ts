/**
 * What the wallet origin remembers about the passkeys on this device, and how it names new ones.
 *
 * The external user id a device stores names whom it last knew, not which passkeys it holds: a
 * passkey added from another device (WM-18) belongs to another user, and a returning user's synced
 * passkey reaches a browser that stores no id at all. So the connect screen asks the browser for
 * whichever passkey the device holds once it knows the device holds one, rather than trusting the
 * stored id. Storage can be blocked or cleared; then the device is treated as holding none, and the
 * user can still choose "use a passkey I already have".
 */

const KEY = "giano:passkey-on-device";

/** Records that this device holds a passkey for the wallet origin: after a sign-in, a registration or a claim. */
export function markPasskeyOnDevice(): void {
	try {
		localStorage.setItem(KEY, "1");
	} catch {
		// Storage blocked: the connect screen then offers the held-passkey sign-in as the alternative.
	}
}

/** True when this device is known to hold a passkey for the wallet origin. */
export function hasPasskeyOnDevice(): boolean {
	try {
		return localStorage.getItem(KEY) === "1";
	} catch {
		return false;
	}
}

/**
 * The name a new passkey shows in the browser's and the password manager's picker. Every passkey for
 * a wallet origin shares its relying party, so the name is what tells them apart: the wallet it
 * belongs to when that is known (a passkey added to an existing wallet), else the day it was made
 * (a first passkey, whose wallet is derived from it afterwards).
 */
export function passkeyName(
	brand: string,
	walletAddress?: string,
	now: Date = new Date(),
): string {
	if (walletAddress && /^0x[0-9a-fA-F]{40}$/.test(walletAddress)) {
		return `${brand} · ${walletAddress.slice(0, 6)}…${walletAddress.slice(-4)}`;
	}
	return `${brand} · ${now.toISOString().slice(0, 10)}`;
}
