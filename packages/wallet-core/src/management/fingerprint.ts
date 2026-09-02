import type { Hex } from 'viem';
import { hexToBytes, keccak256 } from 'viem';

/**
 * The fingerprint both devices display during a cross-device addition (WM-20, D8).
 *
 * Derived from the owner bytes themselves — for a passkey, the 64-byte x‖y public key —
 * so each side computes it from the key AS IT HOLDS IT: the new device from the key it
 * just created, the authorising device from the key it received through the backend. The
 * comparison is what lets the USER, rather than the party carrying the key, choose what
 * gets added; without it the operator could substitute a key and BR-03 falls.
 *
 * Six characters of Crockford base32 (no I, L, O, U — it survives being read aloud),
 * grouped as XXX-XXX. 30 bits: enough that a substituted key cannot be made to collide
 * on the fly against a fingerprint already on the user's other screen, small enough that
 * a person actually compares all of it.
 */
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export function ownerFingerprint(ownerBytes: Hex): string {
  const digest = hexToBytes(keccak256(ownerBytes));
  let bits = 0n;
  for (let i = 0; i < 5; i++) bits = (bits << 8n) | BigInt(digest[i]);
  let code = '';
  for (let i = 0; i < 6; i++) {
    code = ALPHABET[Number(bits & 31n)] + code;
    bits >>= 5n;
  }
  return `${code.slice(0, 3)}-${code.slice(3)}`;
}
