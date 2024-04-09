import crypto from 'crypto';

export const createKeypair = () => {
  const keyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  // Export the public key in uncompressed format
  const { publicKey } = keyPair;
  const publicKeyBuffer = publicKey.export({ type: 'spki', format: 'der' });

  // Extract the X and Y coordinates
  // The first byte is 0x04 (indicating an uncompressed key), followed by the X and Y coordinates (each 32 bytes for P-256)
  const x = publicKeyBuffer.subarray(27, 59); // Skip the prefix and SPKI structure to get X
  const y = publicKeyBuffer.subarray(59, 91); // Immediately following X is Y

  return { x, y, keyPair };
};
