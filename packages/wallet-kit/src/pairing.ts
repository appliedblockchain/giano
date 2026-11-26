/**
 * The link a second device opens to join a wallet (PS-2): the wallet origin with the claim code in
 * the URL fragment. A phone that scans it as a QR code lands on the add-this-device screen with the
 * code filled in.
 *
 * The code sits in the fragment because a browser never sends the fragment to a server, so it stays
 * out of server and proxy logs. It only routes the new device to the pending addition: it is
 * single-use and short-lived, and adding the new passkey still needs the authorising device's
 * signature after the user compares fingerprints (WM-19, WM-20).
 */

const CLAIM_PARAM = "claim";

/** A claim code as a link may carry it: letters, digits and the display hyphen. */
const CLAIM_CODE = /^[0-9A-Za-z-]{4,32}$/;

/**
 * The pairing link for a claim code, on the given wallet origin. Only the origin is kept: the link
 * opens the wallet's root page, whatever path the argument carries.
 */
export function pairingUrl(walletOrigin: string, claimCode: string): string {
	return `${new URL(walletOrigin).origin}/#${CLAIM_PARAM}=${encodeURIComponent(claimCode)}`;
}

/** The claim code a pairing link carries, or null when the URL carries none. */
export function claimCodeFromUrl(url: string): string | null {
	try {
		const fragment = new URL(url).hash.replace(/^#/, "");
		const code = new URLSearchParams(fragment).get(CLAIM_PARAM);
		return code && CLAIM_CODE.test(code) ? code : null;
	} catch {
		return null;
	}
}
