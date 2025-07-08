/**
 * Convert hex string to Uint8Array
 */
export function hexToBytes(hex: string) {
  hex = hex.replace(/^0x/g, '');
  if (hex.length % 2 !== 0) {
    hex = '0' + hex;
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Concatenate multiple Uint8Arrays
 */
export function concatBytes(bytes: Uint8Array[]) {
  const totalLength = bytes.reduce((acc, curr) => acc + curr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const byte of bytes) {
    result.set(byte, offset);
    offset += byte.length;
  }
  return result;
}

/**
 * Convert Uint8Array to hex string
 */
export function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Pad bytes to specified size with leading zeros
 */
export function padBytes(bytes: Uint8Array, size: number) {
  if (bytes.length < size) {
    return concatBytes([new Uint8Array(size - bytes.length).fill(0), bytes]);
  }
  return bytes;
}

/**
 * Helper function to serialize with BigInt support
 */
export function serializeWithBigInt(obj: any): string {
  return JSON.stringify(obj, (key, value) =>
    typeof value === 'bigint' ? value.toString() : value
  );
} 