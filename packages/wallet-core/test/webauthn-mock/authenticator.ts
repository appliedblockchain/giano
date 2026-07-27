/**
 * A software WebAuthn platform authenticator backed by *real* WebCrypto P-256
 * keys. It emulates a passkey device faithfully enough that `ox`/`viem` and a
 * real server (`@simplewebauthn`) accept its output:
 *
 *  - registration returns a real SPKI public key (`getPublicKey()`) and a valid
 *    CBOR `attestationObject` (fmt "none") embedding the COSE_Key,
 *  - authentication returns real DER-encoded ECDSA signatures over
 *    `authenticatorData || SHA-256(clientDataJSON)` that verify against the key.
 *
 * Nothing here is faked: sign/verify use `crypto.subtle` with actual keypairs,
 * so a signature this mock produces is cryptographically valid.
 */
import { cborMap, encodeCbor } from './cbor';
import { rawSignatureToDer } from './der';

const subtle = globalThis.crypto.subtle;

// ---------------------------------------------------------------------------
// byte helpers
// ---------------------------------------------------------------------------

const toArrayBuffer = (u8: Uint8Array): ArrayBuffer =>
  u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as ArrayBuffer;

const asUint8 = (source: BufferSource): Uint8Array =>
  source instanceof Uint8Array ? source : new Uint8Array(source instanceof ArrayBuffer ? source : source.buffer);

export const toBase64Url = (bytes: Uint8Array): string => {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return Buffer.from(binary, 'binary').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

const bytesToHex = (bytes: Uint8Array): `0x${string}` =>
  `0x${Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')}`;

const bytesEqual = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((byte, i) => byte === b[i]);

const sha256 = async (data: Uint8Array): Promise<Uint8Array> => new Uint8Array(await subtle.digest('SHA-256', data));

const randomBytes = (length: number): Uint8Array => globalThis.crypto.getRandomValues(new Uint8Array(length));

// ---------------------------------------------------------------------------
// stored credential
// ---------------------------------------------------------------------------

type StoredCredential = {
  id: string;
  rawId: Uint8Array;
  keyPair: CryptoKeyPair;
  spki: Uint8Array;
  x: Uint8Array;
  y: Uint8Array;
  userHandle: Uint8Array;
  rpId: string;
  counter: number;
};

export type MockAuthenticatorOptions = {
  /** Origin embedded into clientDataJSON. Default `https://localhost`. */
  origin?: string;
};

export class MockAuthenticator {
  readonly origin: string;
  private readonly credentials = new Map<string, StoredCredential>();

  constructor(options: MockAuthenticatorOptions = {}) {
    this.origin = options.origin ?? 'https://localhost';
  }

  /** All resident credentials, in creation order. */
  list(): StoredCredential[] {
    return [...this.credentials.values()];
  }

  /** Public-key coordinates for a stored credential, as the wallet-api seam returns them. */
  getPublicKeyXY(rawId: BufferSource): { x: `0x${string}`; y: `0x${string}` } {
    const cred = this.find(asUint8(rawId));
    if (!cred) throw new Error('mock authenticator: unknown credential');
    return { x: bytesToHex(cred.x), y: bytesToHex(cred.y) };
  }

  private find(rawId: Uint8Array): StoredCredential | undefined {
    return this.credentials.get(toBase64Url(rawId));
  }

  private buildAuthenticatorData(rpIdHash: Uint8Array, flags: number, counter: number, attested?: Uint8Array): Uint8Array {
    const header = new Uint8Array(37);
    header.set(rpIdHash, 0);
    header[32] = flags;
    header[33] = (counter >>> 24) & 0xff;
    header[34] = (counter >>> 16) & 0xff;
    header[35] = (counter >>> 8) & 0xff;
    header[36] = counter & 0xff;
    if (!attested) return header;
    const out = new Uint8Array(header.length + attested.length);
    out.set(header, 0);
    out.set(attested, header.length);
    return out;
  }

  // -------------------------------------------------------------------------
  // navigator.credentials.create
  // -------------------------------------------------------------------------

  async create(options: CredentialCreationOptions): Promise<PublicKeyCredential> {
    const publicKey = options.publicKey;
    if (!publicKey) throw new Error('mock authenticator: create requires publicKey options');

    const rpId = publicKey.rp?.id ?? new URL(this.origin).hostname;
    const keyPair = (await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])) as CryptoKeyPair;
    const spki = new Uint8Array(await subtle.exportKey('spki', keyPair.publicKey));
    const raw = new Uint8Array(await subtle.exportKey('raw', keyPair.publicKey)); // 0x04 || x || y
    const x = raw.slice(1, 33);
    const y = raw.slice(33, 65);

    const rawId = randomBytes(20);
    const id = toBase64Url(rawId);
    const userHandle = asUint8(publicKey.user.id);

    // COSE_Key: kty=EC2(2), alg=ES256(-7), crv=P-256(1), x, y
    const coseKey = encodeCbor(cborMap([[1, 2], [3, -7], [-1, 1], [-2, x], [-3, y]]));

    const aaguid = new Uint8Array(16); // all-zero AAGUID (self-attestation, "none" fmt)
    const credIdLen = new Uint8Array([(rawId.length >> 8) & 0xff, rawId.length & 0xff]);
    const attestedCredentialData = new Uint8Array([...aaguid, ...credIdLen, ...rawId, ...coseKey]);

    const rpIdHash = await sha256(new TextEncoder().encode(rpId));
    const FLAG_UP = 0x01;
    const FLAG_UV = 0x04;
    const FLAG_AT = 0x40;
    const authData = this.buildAuthenticatorData(rpIdHash, FLAG_UP | FLAG_UV | FLAG_AT, 0, attestedCredentialData);

    const attestationObject = encodeCbor(cborMap([
      ['fmt', 'none'],
      ['attStmt', cborMap([])],
      ['authData', authData],
    ]));

    const clientDataJSON = new TextEncoder().encode(
      JSON.stringify({ type: 'webauthn.create', challenge: toBase64Url(asUint8(publicKey.challenge)), origin: this.origin, crossOrigin: false }),
    );

    this.credentials.set(id, { id, rawId, keyPair, spki, x, y, userHandle, rpId, counter: 0 });

    const response: AuthenticatorAttestationResponse = {
      clientDataJSON: toArrayBuffer(clientDataJSON),
      attestationObject: toArrayBuffer(attestationObject),
      getAuthenticatorData: () => toArrayBuffer(authData),
      getPublicKey: () => toArrayBuffer(spki),
      getPublicKeyAlgorithm: () => -7,
      getTransports: () => ['internal'],
    } as AuthenticatorAttestationResponse;

    return this.wrapCredential(id, rawId, response);
  }

  // -------------------------------------------------------------------------
  // navigator.credentials.get
  // -------------------------------------------------------------------------

  async get(options: CredentialRequestOptions): Promise<PublicKeyCredential> {
    const publicKey = options.publicKey;
    if (!publicKey) throw new Error('mock authenticator: get requires publicKey options');

    const cred = this.select(publicKey.allowCredentials);
    if (!cred) {
      const error = new Error('No matching credential');
      error.name = 'NotAllowedError';
      throw error;
    }

    cred.counter += 1;
    const rpIdHash = await sha256(new TextEncoder().encode(cred.rpId));
    const FLAG_UP = 0x01;
    const FLAG_UV = 0x04;
    const authData = this.buildAuthenticatorData(rpIdHash, FLAG_UP | FLAG_UV, cred.counter);

    const clientDataJSON = new TextEncoder().encode(
      JSON.stringify({ type: 'webauthn.get', challenge: toBase64Url(asUint8(publicKey.challenge)), origin: this.origin, crossOrigin: false }),
    );

    const signedPayload = new Uint8Array([...authData, ...(await sha256(clientDataJSON))]);
    const rawSignature = new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, cred.keyPair.privateKey, signedPayload));
    const signature = rawSignatureToDer(rawSignature);

    const response: AuthenticatorAssertionResponse = {
      clientDataJSON: toArrayBuffer(clientDataJSON),
      authenticatorData: toArrayBuffer(authData),
      signature: toArrayBuffer(signature),
      userHandle: toArrayBuffer(cred.userHandle),
    } as AuthenticatorAssertionResponse;

    return this.wrapCredential(cred.id, cred.rawId, response);
  }

  /** Picks the credential a `get()` should assert with: honour allowCredentials, else first resident key. */
  private select(allowCredentials?: PublicKeyCredentialDescriptor[]): StoredCredential | undefined {
    if (allowCredentials && allowCredentials.length > 0) {
      for (const descriptor of allowCredentials) {
        const match = this.find(asUint8(descriptor.id));
        if (match) return match;
      }
      return undefined;
    }
    return this.list()[0]; // resident-key discovery
  }

  private wrapCredential(id: string, rawId: Uint8Array, response: AuthenticatorAttestationResponse | AuthenticatorAssertionResponse): PublicKeyCredential {
    return {
      id,
      rawId: toArrayBuffer(rawId),
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response,
      getClientExtensionResults: () => ({}),
    } as unknown as PublicKeyCredential;
  }
}
