import { bytesToHex, type Hex, hexToBytes, isHex } from "viem";
import { GianoError } from "../giano-error";

/** Thrown when a key is not an uncompressed P-256 public key in a shape `parseP256PublicKey` accepts. */
export class InvalidP256PublicKeyError extends GianoError {}

/** The affine coordinates of a P-256 public key, as the account contract stores them. */
export type P256Coordinates = { x: Hex; y: Hex };

/**
 * The shapes a P-256 public key reaches an integrator in. Each may be given as bytes, an
 * `ArrayBuffer` or 0x-prefixed hex:
 *
 * - SPKI DER (91 bytes): what `AuthenticatorAttestationResponse.getPublicKey()` returns.
 * - An uncompressed SEC 1 point (65 bytes, `0x04 ‖ x ‖ y`): WebCrypto's `raw` export.
 * - The bare coordinates (64 bytes, `x ‖ y`): viem's `createWebAuthnCredential().publicKey`.
 */
export type P256PublicKeyInput = Hex | Uint8Array | ArrayBuffer;

// The DER header of a SubjectPublicKeyInfo that holds an uncompressed P-256 point:
//   SEQUENCE { SEQUENCE { OID id-ecPublicKey, OID prime256v1 }, BIT STRING (0 unused bits) }
// DER has one encoding per value, so every such key starts with exactly these 26 bytes,
// followed by the 65-byte uncompressed point.
const P256_SPKI_HEADER = hexToBytes(
	"0x3059301306072a8648ce3d020106082a8648ce3d030107034200",
);
const P256_SPKI_LENGTH = P256_SPKI_HEADER.length + 65;

// Curve parameters of P-256 (secp256r1, FIPS 186-4 §D.1.2.3): y² = x³ − 3x + b (mod p).
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;

/**
 * Turns a WebAuthn / P-256 public key into the `(bytes32 x, bytes32 y)` pair that
 * `addOwnerPublicKey` and `publicKeyOwnerBytes` take.
 *
 * Throws `InvalidP256PublicKeyError` when the input is not one of the shapes in
 * {@link P256PublicKeyInput}, names another algorithm or curve, uses point compression,
 * or is not a point on the P-256 curve.
 *
 * @example
 * ```ts
 * const response = credential.response as AuthenticatorAttestationResponse;
 * const { x, y } = parseP256PublicKey(response.getPublicKey()!);
 * const data = encodeAddOwnerPublicKey(x, y);
 * ```
 */
export function parseP256PublicKey(key: P256PublicKeyInput): P256Coordinates {
	const point = toUncompressedCoordinates(toBytes(key));
	const x = point.subarray(0, 32);
	const y = point.subarray(32, 64);
	if (!isOnP256Curve(BigInt(bytesToHex(x)), BigInt(bytesToHex(y)))) {
		throw new InvalidP256PublicKeyError(
			"Invalid P-256 public key: the point is not on the P-256 curve",
		);
	}
	return { x: bytesToHex(x), y: bytesToHex(y) };
}

function toBytes(key: P256PublicKeyInput): Uint8Array {
	if (key instanceof Uint8Array) return key;
	if (key instanceof ArrayBuffer) return new Uint8Array(key);
	if (typeof key === "string") {
		if (!isHex(key, { strict: true }) || key.length % 2 !== 0) {
			throw new InvalidP256PublicKeyError(
				"Invalid P-256 public key: a string key must be 0x-prefixed hex with whole bytes",
			);
		}
		return hexToBytes(key);
	}
	throw new InvalidP256PublicKeyError(
		`Invalid P-256 public key: expected hex, a Uint8Array or an ArrayBuffer, got ${key === null ? "null" : typeof key}`,
	);
}

/** Returns the 64 bytes x ‖ y, or throws when `bytes` is not a supported shape. */
function toUncompressedCoordinates(bytes: Uint8Array): Uint8Array {
	if (bytes.length === 64) return bytes;
	if (bytes.length === 65 && bytes[0] === 0x04) return bytes.subarray(1);
	if (bytes.length === P256_SPKI_LENGTH && hasP256SpkiHeader(bytes)) {
		// The header ends just before the point, so the point's 0x04 tag comes next.
		if (bytes[P256_SPKI_HEADER.length] === 0x04) {
			return bytes.subarray(P256_SPKI_HEADER.length + 1);
		}
	}
	if (bytes.length === 33 && (bytes[0] === 0x02 || bytes[0] === 0x03)) {
		throw new InvalidP256PublicKeyError(
			"Invalid P-256 public key: compressed points are not supported; pass the SPKI key or the uncompressed point",
		);
	}
	if (bytes[0] === 0x30) {
		throw new InvalidP256PublicKeyError(
			"Invalid P-256 public key: the SPKI key is not an uncompressed P-256 (ES256) key",
		);
	}
	throw new InvalidP256PublicKeyError(
		`Invalid P-256 public key: expected SPKI DER (91 bytes), an uncompressed point (65 bytes, 0x04 prefix) or x ‖ y (64 bytes), got ${bytes.length} bytes`,
	);
}

function hasP256SpkiHeader(bytes: Uint8Array): boolean {
	return P256_SPKI_HEADER.every((byte, index) => bytes[index] === byte);
}

function isOnP256Curve(x: bigint, y: bigint): boolean {
	if (x >= P || y >= P) return false;
	const mod = (n: bigint) => ((n % P) + P) % P;
	return mod(y * y) === mod(x * x * x - 3n * x + B);
}
