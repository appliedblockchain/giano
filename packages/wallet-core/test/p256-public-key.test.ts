import { bytesToHex, type Hex, hexToBytes } from "viem";
import { describe, expect, it } from "vitest";
import {
	encodeAddOwnerPublicKey,
	InvalidP256PublicKeyError,
	parseP256PublicKey,
	publicKeyOwnerBytes,
} from "../src/management";
import { MockAuthenticator } from "./webauthn-mock";

// A real P-256 key exported by WebCrypto (`exportKey("spki")` and `exportKey("raw")`).
const SPKI: Hex =
	"0x3059301306072a8648ce3d020106082a8648ce3d0301070342000495aabdaffc34c614e22a07fb517ca35f5e58b07f4263b465fe8b06f3b8efa614475dfea62ecd2e16c255cbeea147a45a7f53287ff831d8ce943d04276b090132";
const X: Hex =
	"0x95aabdaffc34c614e22a07fb517ca35f5e58b07f4263b465fe8b06f3b8efa614";
const Y: Hex =
	"0x475dfea62ecd2e16c255cbeea147a45a7f53287ff831d8ce943d04276b090132";
const UNCOMPRESSED: Hex = `0x04${X.slice(2)}${Y.slice(2)}`;
const XY: Hex = `0x${X.slice(2)}${Y.slice(2)}`;

// A real P-384 key exported by WebCrypto: valid SPKI, wrong curve.
const P384_SPKI: Hex =
	"0x3076301006072a8648ce3d020106052b8104002203620004f4a21d3c04c7c9770a13798aefa492cfe315c9ca88bff2de92f05be1b134b8f094b405cc53f0fd5b869945b3b7acebca7e54806615acde892e03c5310c13511adeaaa028e626fc7be10dc090f7cf38dd62469ac31c46695c2a3b7794ba3a4e6c";

// The P-256 field prime: a coordinate equal to it is out of range.
const P: Hex =
	"0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff";

const toArrayBuffer = (hex: Hex): ArrayBuffer => {
	const bytes = hexToBytes(hex);
	return bytes.buffer.slice(
		bytes.byteOffset,
		bytes.byteOffset + bytes.byteLength,
	) as ArrayBuffer;
};

/** Returns `hex` with byte `index` changed from `expected` to `value`; fails if the fixture moved. */
const withByte = (
	hex: Hex,
	index: number,
	expected: number,
	value: number,
): Hex => {
	const bytes = hexToBytes(hex);
	if (bytes[index] !== expected) {
		throw new Error(
			`fixture byte ${index} is 0x${bytes[index].toString(16)}, expected 0x${expected.toString(16)}`,
		);
	}
	bytes[index] = value;
	return bytesToHex(bytes);
};

describe("parseP256PublicKey", () => {
	it("reads the SPKI key from a WebAuthn registration (getPublicKey())", async () => {
		const authenticator = new MockAuthenticator();
		const credential = await authenticator.create({
			publicKey: {
				rp: { id: "localhost", name: "giano" },
				user: { id: new Uint8Array([1]), name: "a", displayName: "a" },
				challenge: new Uint8Array([1, 2, 3]),
				pubKeyCredParams: [{ type: "public-key", alg: -7 }],
			},
		} as CredentialCreationOptions);
		const response = credential.response as AuthenticatorAttestationResponse;

		const spki = response.getPublicKey();
		if (!spki) throw new Error("mock authenticator returned no SPKI key");

		expect(parseP256PublicKey(spki)).toEqual(
			authenticator.getPublicKeyXY(credential.rawId),
		);
	});

	it.each([
		["SPKI hex", SPKI],
		["SPKI bytes", hexToBytes(SPKI)],
		["SPKI ArrayBuffer", toArrayBuffer(SPKI)],
		["uncompressed point hex", UNCOMPRESSED],
		["uncompressed point bytes", hexToBytes(UNCOMPRESSED)],
		["x ‖ y hex (viem's createWebAuthnCredential)", XY],
		["x ‖ y bytes", hexToBytes(XY)],
		["uppercase hex", `0x${SPKI.slice(2).toUpperCase()}` as Hex],
	])("accepts %s", (_, key) => {
		expect(parseP256PublicKey(key)).toEqual({ x: X, y: Y });
	});

	it("reads an SPKI key held in a subarray of a larger buffer", () => {
		const padded = new Uint8Array(100);
		padded.set(hexToBytes(SPKI), 5);
		expect(parseP256PublicKey(padded.subarray(5, 96))).toEqual({ x: X, y: Y });
	});

	it("returns coordinates that encode the owner the contract expects", () => {
		const { x, y } = parseP256PublicKey(SPKI);
		expect(publicKeyOwnerBytes(x, y)).toBe(XY);
		expect(encodeAddOwnerPublicKey(x, y)).toBe(encodeAddOwnerPublicKey(X, Y));
	});

	describe("rejects", () => {
		const flipLastByte = (hex: Hex): Hex => {
			const bytes = hexToBytes(hex);
			bytes[bytes.length - 1] ^= 0x01;
			return bytesToHex(bytes);
		};

		it.each([
			[
				"a point that is not on the curve",
				flipLastByte(XY),
				/not on the P-256 curve/,
			],
			[
				"an SPKI key whose point is not on the curve",
				flipLastByte(SPKI),
				/not on the P-256 curve/,
			],
			[
				"a coordinate equal to the field prime",
				`0x${P.slice(2)}${Y.slice(2)}` as Hex,
				/not on the P-256 curve/,
			],
			[
				"the all-zero point",
				`0x${"00".repeat(64)}` as Hex,
				/not on the P-256 curve/,
			],
			[
				"a compressed point",
				`0x02${X.slice(2)}` as Hex,
				/compressed points are not supported/,
			],
			[
				"a 65-byte key without the 0x04 tag",
				`0x02${XY.slice(2)}` as Hex,
				/got 65 bytes/,
			],
			[
				"an SPKI key on another curve (P-384)",
				P384_SPKI,
				/not an uncompressed P-256/,
			],
			// The SPKI header: 30 59 | 30 13 | 06 07 <id-ecPublicKey> (bytes 4–12)
			// | 06 08 <prime256v1: 2a 86 48 ce 3d 03 01 07> (bytes 13–22) | 03 42 00 (bytes 23–25),
			// then the point's 0x04 tag at byte 26. Each case keeps the 91-byte length.
			[
				"an SPKI key with another curve OID of the same length",
				withByte(SPKI, 22, 0x07, 0x08),
				/not an uncompressed P-256/,
			],
			[
				"an SPKI key with another algorithm OID",
				withByte(SPKI, 12, 0x01, 0x02),
				/not an uncompressed P-256/,
			],
			[
				"an SPKI key whose BIT STRING has unused bits",
				withByte(SPKI, 25, 0x00, 0x01),
				/not an uncompressed P-256/,
			],
			[
				"an SPKI key whose point is not tagged 0x04",
				withByte(SPKI, 26, 0x04, 0x02),
				/not an uncompressed P-256/,
			],
			["an empty key", "0x" as Hex, /got 0 bytes/],
			["a key of the wrong length", `0x${XY.slice(4)}` as Hex, /got 63 bytes/],
			["odd-length hex", `${XY}0` as Hex, /whole bytes/],
			["a string that is not hex", "not-a-key" as Hex, /0x-prefixed hex/],
		])("%s", (_, key, message) => {
			expect(() => parseP256PublicKey(key)).toThrow(InvalidP256PublicKeyError);
			expect(() => parseP256PublicKey(key)).toThrow(message);
		});

		it("a missing key (getPublicKey() returned null)", () => {
			expect(() => parseP256PublicKey(null as unknown as Hex)).toThrow(
				/got null/,
			);
		});
	});
});
