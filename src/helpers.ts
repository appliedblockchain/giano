import * as base64url from '@cfworker/base64url';

const { decode: fromBase64Url, encode: toBase64Url } = base64url;

const encoder = new TextEncoder();
const decoder = new TextDecoder();
export const encode = encoder.encode.bind(encoder);
export const decode = decoder.decode.bind(decoder);

export const byteStringToBuffer = (byteString: string) => Uint8Array.from(byteString, (e) => e.charCodeAt(0)).buffer;

export const bufferToByteString = (buffer: ArrayBuffer) => String.fromCharCode(...new Uint8Array(buffer));

export const safeDecode = (data: string): Uint8Array => encode(fromBase64Url(data));
export const safeEncode = (data: ArrayBuffer): string => toBase64Url(decode(data));
export const safeByteDecode = (data: string): ArrayBufferLike => byteStringToBuffer(fromBase64Url(data));
export const safeByteEncode = (data: ArrayBuffer): string => toBase64Url(bufferToByteString(data));

export const base64URLToBuffer = (base64URL: string) => {
  const base64 = base64URL.replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (base64.length % 4)) % 4;
  return Uint8Array.from(atob(base64.padEnd(base64.length + padLen, '=')), (c) => c.charCodeAt(0));
};

export const bufferToBase64URL = (buffer: Uint8Array) => {
  const bytes = new Uint8Array(buffer);
  let string = '';
  bytes.forEach((b) => (string += String.fromCharCode(b)));
  const base64 = btoa(string);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
};

export const base64ToPem = (b64cert) => {
  let pemcert = '';
  for (let i = 0; i < b64cert.length; i += 64) pemcert += b64cert.slice(i, i + 64) + '\n';

  return '-----BEGIN CERTIFICATE-----\n' + pemcert + '-----END CERTIFICATE-----';
};

export const encodeChallenge = (challenge: string) => bufferToBase64URL(new TextEncoder().encode(challenge));
// export const decodeChallenge = (challenge: string) => new TextDecoder().decode(challenge)

export const fetchPost = async (url: string, data: any) => {
  const response = await fetch(url, {
    method: 'POST',
    mode: 'cors',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });

  const result = await response.json();
  return result;
};

export const areBytewiseEqual = (a, b) => indexedDB.cmp(a, b) === 0;

export const convertDERSignatureToECDSASignature = (DERSignature: ArrayLike<number> | ArrayBufferLike): ArrayBuffer => {
  const signatureBytes = new Uint8Array(DERSignature);

  const rStart = 4;
  const rLength = signatureBytes[3];
  const rEnd = rStart + rLength;
  const DEREncodedR = signatureBytes.slice(rStart, rEnd);
  // DER encoded 32 bytes integers can have leading 0x00s or be smaller than 32 bytes
  const r = decodeDERInteger(DEREncodedR, 32);

  const sStart = rEnd + 2;
  const sEnd = signatureBytes.byteLength;
  const DEREncodedS = signatureBytes.slice(sStart, sEnd);
  // repeat the process
  const s = decodeDERInteger(DEREncodedS, 32);

  const ECDSASignature = new Uint8Array([...r, ...s]);
  return ECDSASignature.buffer;
};

export const decodeDERInteger = (integerBytes: Uint8Array, expectedLength: number): Uint8Array => {
  if (integerBytes.byteLength === expectedLength) return integerBytes;
  if (integerBytes.byteLength < expectedLength) {
    return new Uint8Array([
      // add leading 0x00s if smaller than expected length
      ...new Uint8Array(expectedLength - integerBytes.byteLength).fill(0),
      ...integerBytes,
    ]);
  }
  // remove leading 0x00s if larger then expected length
  return integerBytes.slice(-32);
};

export const concatenateBuffers = (a, b) => new Uint8Array([...a, ...b]);
