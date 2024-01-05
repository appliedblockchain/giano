export const byteStringToBuffer = (byteString: string) => Uint8Array.from(byteString, (e) => e.charCodeAt(0)).buffer;
export const bufferToByteString = (buffer: ArrayBuffer) => String.fromCharCode(...new Uint8Array(buffer));

export const base64URLToBuffer = (base64URL: string) => {
  const base64 = base64URL.replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (base64.length % 4)) % 4;
  return Uint8Array.from(atob(base64.padEnd(base64.length + padLen, '=')), (c) => c.charCodeAt(0));
};

export function bufferToBigInt(buf: ArrayBuffer | Uint8Array | Buffer): bigint {
  let bits = 8n;
  if (ArrayBuffer.isView(buf)) bits = BigInt(buf.BYTES_PER_ELEMENT * 8);
  else buf = new Uint8Array(buf);

  let ret = 0n;
  for (const i of (buf as Uint8Array | Buffer).values()) {
    const bi = BigInt(i);
    ret = (ret << bits) + bi;
  }
  return ret;
}

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
