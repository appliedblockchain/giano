export const byteStringToBuffer = (byteString: string) => Uint8Array.from(byteString, (e) => e.charCodeAt(0)).buffer;
export const bufferToByteString = (buffer: ArrayBuffer) => String.fromCharCode(...new Uint8Array(buffer));

// export const safeByteDecode = (data: string): ArrayBufferLike => byteStringToBuffer(fromBase64Url(data));
// export const safeByteEncode = (data: ArrayBuffer): string => toBase64Url(bufferToByteString(data));

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

// export const encodeChallenge = (challenge: string) => bufferToBase64URL(new TextEncoder().encode(challenge));
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

// export const areBytewiseEqual = (a: Uint8Array, b: Uint8Array) => indexedDB.cmp(a, b) === 0;

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

export const fromAsn1DERtoRSSignature = (signature: ArrayBuffer, hashBitLength: number) => {
  if (hashBitLength % 8 !== 0) {
    throw new Error(`hashBitLength ${hashBitLength} is not a multiple of 8`);
  }

  const sig = new Uint8Array(signature);

  if (sig[0] != 48) {
    throw new Error('Invalid ASN.1 DER signature');
  }

  const rStart = 4;
  const rLength = sig[3];
  const sStart = rStart + rLength + 2;
  const sLength = sig[rStart + rLength + 1];

  let r = sig.slice(rStart, rStart + rLength);
  let s = sig.slice(sStart, sStart + sLength);

  // Remove any 0 padding
  for (const i of r.slice()) {
    if (i !== 0) {
      break;
    }
    r = r.slice(1);
  }
  for (const i of s.slice()) {
    if (i !== 0) {
      break;
    }
    s = s.slice(1);
  }

  const padding = hashBitLength / 8;

  if (r.length > padding || s.length > padding) {
    throw new Error(`Invalid r or s value bigger than allowed max size of ${padding}`);
  }

  const rPadding = padding - r.length;
  const sPadding = padding - s.length;

  return concatBuffers(new Uint8Array(rPadding).fill(0), r, new Uint8Array(sPadding).fill(0), s);
};
