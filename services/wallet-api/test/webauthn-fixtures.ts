/**
 * Deterministic WebAuthn fixtures: real P-256 keys and hand-encoded CBOR
 * attestation/assertion payloads that pass @simplewebauthn verification. This gives
 * the integration tests true end-to-end ceremony coverage without a browser.
 */
import { createHash, createSign, generateKeyPairSync, randomBytes, type KeyObject } from 'node:crypto';

const sha256 = (data: Buffer | string) => createHash('sha256').update(data).digest();
export const b64url = (buf: Buffer) => buf.toString('base64url');

// --- minimal CBOR encoder (only what COSE/attestation needs) ---
function cborUint(major: number, value: number): Buffer {
  if (value < 24) return Buffer.from([(major << 5) | value]);
  if (value < 256) return Buffer.from([(major << 5) | 24, value]);
  if (value < 65536) {
    const b = Buffer.alloc(3);
    b[0] = (major << 5) | 25;
    b.writeUInt16BE(value, 1);
    return b;
  }
  const b = Buffer.alloc(5);
  b[0] = (major << 5) | 26;
  b.writeUInt32BE(value, 1);
  return b;
}

type CborValue = number | string | Buffer | Map<number | string, CborValue> | { [k: string]: CborValue };

export function cborEncode(value: CborValue): Buffer {
  if (typeof value === 'number') {
    if (value >= 0) return cborUint(0, value);
    return cborUint(1, -value - 1);
  }
  if (typeof value === 'string') return Buffer.concat([cborUint(3, Buffer.byteLength(value)), Buffer.from(value)]);
  if (Buffer.isBuffer(value)) return Buffer.concat([cborUint(2, value.length), value]);
  const entries = value instanceof Map ? [...value.entries()] : Object.entries(value);
  const parts: Buffer[] = [cborUint(5, entries.length)];
  for (const [k, v] of entries) {
    parts.push(cborEncode(typeof k === 'string' ? k : Number(k)));
    parts.push(cborEncode(v));
  }
  return Buffer.concat(parts);
}

export type TestAuthenticator = {
  credentialId: Buffer;
  credentialIdB64: string;
  privateKey: KeyObject;
  publicKeyX: Buffer;
  publicKeyY: Buffer;
  counter: number;
};

export function createAuthenticator(): TestAuthenticator {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string; y: string };
  return {
    credentialId: randomBytes(32),
    credentialIdB64: '',
    privateKey,
    publicKeyX: Buffer.from(jwk.x, 'base64url'),
    publicKeyY: Buffer.from(jwk.y, 'base64url'),
    counter: 0,
  };
}

function coseKey(auth: TestAuthenticator): Buffer {
  const map = new Map<number, CborValue>([
    [1, 2], // kty: EC2
    [3, -7], // alg: ES256
    [-1, 1], // crv: P-256
    [-2, auth.publicKeyX],
    [-3, auth.publicKeyY],
  ]);
  return cborEncode(map);
}

function authDataForRegistration(rpId: string, auth: TestAuthenticator): Buffer {
  const rpIdHash = sha256(rpId);
  const flags = Buffer.from([0x45]); // UP | UV | AT
  const counter = Buffer.alloc(4);
  const aaguid = Buffer.alloc(16);
  const credIdLen = Buffer.alloc(2);
  credIdLen.writeUInt16BE(auth.credentialId.length);
  return Buffer.concat([rpIdHash, flags, counter, aaguid, credIdLen, auth.credentialId, coseKey(auth)]);
}

export function makeRegistrationResponse(auth: TestAuthenticator, opts: { challenge: string; origin: string; rpId: string }) {
  const clientDataJSON = Buffer.from(
    JSON.stringify({ type: 'webauthn.create', challenge: opts.challenge, origin: opts.origin, crossOrigin: false }),
  );
  const attestationObject = cborEncode({
    fmt: 'none',
    attStmt: {},
    authData: authDataForRegistration(opts.rpId, auth),
  });
  return {
    id: b64url(auth.credentialId),
    rawId: b64url(auth.credentialId),
    type: 'public-key' as const,
    response: {
      clientDataJSON: b64url(clientDataJSON),
      attestationObject: b64url(attestationObject),
      transports: ['internal'],
    },
    clientExtensionResults: {},
  };
}

export function makeAuthenticationResponse(
  auth: TestAuthenticator,
  opts: { challenge: string; origin: string; rpId: string; counter?: number },
) {
  const clientDataJSON = Buffer.from(
    JSON.stringify({ type: 'webauthn.get', challenge: opts.challenge, origin: opts.origin, crossOrigin: false }),
  );
  const rpIdHash = sha256(opts.rpId);
  const flags = Buffer.from([0x05]); // UP | UV
  const counter = Buffer.alloc(4);
  counter.writeUInt32BE(opts.counter ?? 0);
  const authenticatorData = Buffer.concat([rpIdHash, flags, counter]);

  const signer = createSign('SHA256');
  signer.update(Buffer.concat([authenticatorData, sha256(clientDataJSON)]));
  const signature = signer.sign(auth.privateKey); // DER-encoded, as WebAuthn requires

  return {
    id: b64url(auth.credentialId),
    rawId: b64url(auth.credentialId),
    type: 'public-key' as const,
    response: {
      clientDataJSON: b64url(clientDataJSON),
      authenticatorData: b64url(authenticatorData),
      signature: b64url(signature),
    },
    clientExtensionResults: {},
  };
}
