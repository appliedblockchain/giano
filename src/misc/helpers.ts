import { ECDSASigValue } from '@peculiar/asn1-ecc';
import { AsnParser } from '@peculiar/asn1-schema';

export const byteStringToBuffer = (byteString: string) => Uint8Array.from(byteString, (e) => e.charCodeAt(0)).buffer;
export const bufferToByteString = (buffer: ArrayBuffer) => String.fromCharCode(...new Uint8Array(buffer));

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

export const fetchPost = async (url: string, data: any) => {
  const response = await fetch(url, {
    method: 'POST',
    mode: 'cors',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });

  const result = await response.json();
  if (!response.ok) throw new Error(result);
  return result;
};

export const concatenateBuffers = (a: Uint8Array, b: Uint8Array) => new Uint8Array([...a, ...b]);

export const concatBuffers = (...buffers: ArrayBuffer[]) => {
  const length = buffers.reduce((acc, b) => acc + b.byteLength, 0);
  const tmp = new Uint8Array(length);

  let prev = 0;
  for (const buffer of buffers) {
    tmp.set(new Uint8Array(buffer), prev);
    prev += buffer.byteLength;
  }

  return tmp.buffer;
};

export const areBytewiseEqual = (a: Uint8Array, b: Uint8Array) => {
  if (a.byteLength != b.byteLength) return false;
  const dv1 = new Int8Array(a);
  const dv2 = new Int8Array(b);
  for (let i = 0; i != a.byteLength; i++) {
    if (dv1[i] != dv2[i]) return false;
  }
  return true;
};

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
  // add leading 0x00s if smaller than expected length
  if (integerBytes.byteLength < expectedLength) return new Uint8Array([...new Uint8Array(expectedLength - integerBytes.byteLength).fill(0), ...integerBytes]);
  // remove leading 0x00s if larger than expected length
  else return integerBytes.slice(-32);
};

export function bufToBn(buf) {
  const hex: string[] = [];
  const u8 = Uint8Array.from(buf);

  u8.forEach(function (i) {
    let h = i.toString(16);
    if (h.length % 2) {
      h = '0' + h;
    }
    hex.push(h);
  });

  return BigInt('0x' + hex.join(''));
}

export const getPublicKeyFromBytes = async (publicKeyBytes: string): Promise<bigint[]> => {
  const cap = {
    name: 'ECDSA',
    namedCurve: 'P-256',
    hash: 'SHA-256',
  };
  const pkeybytes = base64URLToBuffer(publicKeyBytes);
  const pkey = await crypto.subtle.importKey('spki', pkeybytes, cap, true, ['verify']);
  const jwk = await crypto.subtle.exportKey('jwk', pkey);
  if (jwk.x && jwk.y) return [bufToBn(base64URLToBuffer(jwk.x)), bufToBn(base64URLToBuffer(jwk.y))];
  else throw new Error('Invalid public key');
};

function shouldRemoveLeadingZero(bytes: Uint8Array): boolean {
  return bytes[0] === 0x0 && (bytes[1] & (1 << 7)) !== 0;
}

export const getMessageSignature = (authResponseSignature: string): bigint[] => {
  // See https://github.dev/MasterKale/SimpleWebAuthn/blob/master/packages/server/src/helpers/iso/isoCrypto/verifyEC2.ts
  // for extraction of the r and s bytes from the raw signature buffer
  const parsedSignature = AsnParser.parse(base64URLToBuffer(authResponseSignature), ECDSASigValue);

  let rBytes = new Uint8Array(parsedSignature.r);
  let sBytes = new Uint8Array(parsedSignature.s);

  if (shouldRemoveLeadingZero(rBytes)) {
    rBytes = rBytes.slice(1);
  }

  if (shouldRemoveLeadingZero(sBytes)) {
    sBytes = sBytes.slice(1);
  }

  // r and s values
  return [bufToBn(rBytes), bufToBn(sBytes)];
};
