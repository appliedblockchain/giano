import type { Hex } from "viem";
import { hexToBytes, keccak256 } from "viem";

/**
 * The fingerprint both devices display during a cross-device addition (WM-20, D8).
 *
 * Derived from the owner bytes themselves — for a passkey, the 64-byte x‖y public key —
 * so each side computes it from the key AS IT HOLDS IT: the new device from the key it
 * just created, the authorising device from the key it received through the backend. The
 * comparison is what lets the USER, rather than the party carrying the key, choose what
 * gets added; without it the operator could substitute a key and BR-03 falls.
 *
 * Sixteen characters of Crockford base32 (no I, L, O, U — it survives being read aloud),
 * grouped as XXXX-XXXX-XXXX-XXXX: the first 80 bits of keccak256 of the owner bytes.
 *
 * The length is set by the attacker the comparison exists to stop. The operator relays the
 * new key, so it holds the genuine key first and decides when the authorising device sees
 * the slot as filled. The slot's expiry gives it no deadline either: the backend enforces
 * that expiry, and the backend is the operator. So it can search offline, for as long as it
 * likes, for a key of its own with the same fingerprint. Each attempt costs one P-256 point
 * addition and one keccak256. At 30 bits that search takes minutes on a GPU; at 80 bits it
 * takes about 2^80 attempts, which no one can afford for one wallet.
 */
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const FINGERPRINT_BYTES = 10; // 80 bits
const FINGERPRINT_CHARS = (FINGERPRINT_BYTES * 8) / 5; // 16 base32 characters
const GROUP_SIZE = 4;

export function ownerFingerprint(ownerBytes: Hex): string {
	const digest = hexToBytes(keccak256(ownerBytes));
	let bits = 0n;
	for (let i = 0; i < FINGERPRINT_BYTES; i++)
		bits = (bits << 8n) | BigInt(digest[i]);
	let code = "";
	for (let i = 0; i < FINGERPRINT_CHARS; i++) {
		code = ALPHABET[Number(bits & 31n)] + code;
		bits >>= 5n;
	}
	const groups: string[] = [];
	for (let i = 0; i < code.length; i += GROUP_SIZE)
		groups.push(code.slice(i, i + GROUP_SIZE));
	return groups.join("-");
}
