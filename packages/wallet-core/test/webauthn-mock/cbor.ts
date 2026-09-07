/**
 * Minimal CBOR (RFC 8949) encoder/decoder — just enough to build and verify a
 * faithful WebAuthn `attestationObject` (`{ fmt, attStmt, authData }`) and the
 * embedded COSE_Key. Not a general-purpose implementation.
 */

/** A COSE map preserves integer (incl. negative) keys and order, so model it as pairs. */
export type CborMap = { __cborMap: Array<[CborValue, CborValue]> };
export type CborValue = number | string | Uint8Array | CborValue[] | CborMap;

export const cborMap = (pairs: Array<[CborValue, CborValue]>): CborMap => ({ __cborMap: pairs });

const concat = (chunks: Uint8Array[]): Uint8Array => {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
};

/** Encodes the major type + argument (length/value) header. */
const header = (majorType: number, argument: number): Uint8Array => {
  const mt = majorType << 5;
  if (argument < 24) return new Uint8Array([mt | argument]);
  if (argument < 0x100) return new Uint8Array([mt | 24, argument]);
  if (argument < 0x10000) return new Uint8Array([mt | 25, argument >> 8, argument & 0xff]);
  return new Uint8Array([mt | 26, (argument >>> 24) & 0xff, (argument >> 16) & 0xff, (argument >> 8) & 0xff, argument & 0xff]);
};

const isCborMap = (value: CborValue): value is CborMap =>
  typeof value === 'object' && value !== null && '__cborMap' in (value as object);

export function encodeCbor(value: CborValue): Uint8Array {
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) throw new Error('cbor: only integers supported');
    if (value >= 0) return header(0, value);
    return header(1, -value - 1); // negative integer major type
  }
  if (typeof value === 'string') {
    const bytes = new TextEncoder().encode(value);
    return concat([header(3, bytes.length), bytes]);
  }
  if (value instanceof Uint8Array) {
    return concat([header(2, value.length), value]);
  }
  if (Array.isArray(value)) {
    return concat([header(4, value.length), ...value.map(encodeCbor)]);
  }
  if (isCborMap(value)) {
    const pairs = value.__cborMap;
    return concat([header(5, pairs.length), ...pairs.flatMap(([k, v]) => [encodeCbor(k), encodeCbor(v)])]);
  }
  throw new Error('cbor: unsupported value');
}

/** Tiny decoder returning [value, bytesConsumed] — used only by the mock's self-tests. */
export function decodeCbor(bytes: Uint8Array, offset = 0): [CborValue, number] {
  const first = bytes[offset];
  const majorType = first >> 5;
  const info = first & 0x1f;
  let argument = info;
  let cursor = offset + 1;
  if (info === 24) {
    argument = bytes[cursor];
    cursor += 1;
  } else if (info === 25) {
    argument = (bytes[cursor] << 8) | bytes[cursor + 1];
    cursor += 2;
  } else if (info === 26) {
    argument = (bytes[cursor] * 0x1000000) + (bytes[cursor + 1] << 16) + (bytes[cursor + 2] << 8) + bytes[cursor + 3];
    cursor += 4;
  }

  switch (majorType) {
    case 0:
      return [argument, cursor - offset];
    case 1:
      return [-argument - 1, cursor - offset];
    case 2: {
      const slice = bytes.slice(cursor, cursor + argument);
      return [slice, cursor + argument - offset];
    }
    case 3: {
      const slice = bytes.slice(cursor, cursor + argument);
      return [new TextDecoder().decode(slice), cursor + argument - offset];
    }
    case 4: {
      const items: CborValue[] = [];
      for (let i = 0; i < argument; i++) {
        const [item, consumed] = decodeCbor(bytes, cursor);
        items.push(item);
        cursor += consumed;
      }
      return [items, cursor - offset];
    }
    case 5: {
      const pairs: Array<[CborValue, CborValue]> = [];
      for (let i = 0; i < argument; i++) {
        const [k, kc] = decodeCbor(bytes, cursor);
        cursor += kc;
        const [v, vc] = decodeCbor(bytes, cursor);
        cursor += vc;
        pairs.push([k, v]);
      }
      return [cborMap(pairs), cursor - offset];
    }
    default:
      throw new Error(`cbor: unsupported major type ${majorType}`);
  }
}
