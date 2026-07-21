/**
 * ASN.1 DER helpers for ECDSA signatures. WebCrypto's `subtle.sign` emits raw
 * IEEE-P1363 `r || s` (64 bytes for P-256), but real WebAuthn authenticators
 * return DER-encoded `SEQUENCE { INTEGER r, INTEGER s }` — so the mock converts,
 * exactly as a hardware key would.
 */

/**
 * Encodes a fixed-width 32-byte big-endian value as a DER INTEGER, prepending a
 * 0x00 sign byte when the MSB is set. Kept fixed-width (32 or 33 bytes) rather
 * than minimally stripped: WebAuthn consumers such as ox's `parseAsn1Signature`
 * assume a 32-byte `r`, so a stripped, shorter integer would misalign them.
 */
function toDerInteger(bytes: Uint8Array): Uint8Array {
  let content = bytes;
  if (content[0] & 0x80) {
    const padded = new Uint8Array(content.length + 1);
    padded.set(content, 1); // prepend 0x00 so the value stays positive
    content = padded;
  }
  const out = new Uint8Array(content.length + 2);
  out[0] = 0x02; // INTEGER tag
  out[1] = content.length;
  out.set(content, 2);
  return out;
}

/** raw `r || s` (64 bytes) → DER `SEQUENCE { INTEGER r, INTEGER s }`. */
export function rawSignatureToDer(raw: Uint8Array): Uint8Array {
  if (raw.length !== 64) throw new Error(`expected 64-byte raw signature, got ${raw.length}`);
  const r = toDerInteger(raw.slice(0, 32));
  const s = toDerInteger(raw.slice(32, 64));
  const body = new Uint8Array(r.length + s.length);
  body.set(r, 0);
  body.set(s, r.length);
  const out = new Uint8Array(body.length + 2);
  out[0] = 0x30; // SEQUENCE tag
  out[1] = body.length; // always < 128 for P-256
  out.set(body, 2);
  return out;
}

/** DER `SEQUENCE { INTEGER r, INTEGER s }` → raw `r || s` (64 bytes). Mirror of the above, for self-tests. */
export function derSignatureToRaw(der: Uint8Array): Uint8Array {
  if (der[0] !== 0x30) throw new Error('not a DER sequence');
  let cursor = 2;
  const readInt = (): Uint8Array => {
    if (der[cursor] !== 0x02) throw new Error('expected DER integer');
    const len = der[cursor + 1];
    let value = der.slice(cursor + 2, cursor + 2 + len);
    cursor += 2 + len;
    if (value.length > 32) value = value.slice(value.length - 32); // drop sign byte
    const padded = new Uint8Array(32);
    padded.set(value, 32 - value.length);
    return padded;
  };
  const r = readInt();
  const s = readInt();
  const out = new Uint8Array(64);
  out.set(r, 0);
  out.set(s, 32);
  return out;
}
