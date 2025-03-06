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

// Add type definition for WebAuthn response format
interface AuthenticatorAssertionResponse {
  clientDataJSON: string | Buffer;
  authenticatorData: Buffer;
  signature: Buffer;
  userHandle: null;
}

export const signWebAuthnChallenge = (privateKey: crypto.KeyObject, challenge: Uint8Array): AuthenticatorAssertionResponse => {
  // Step 2: Prepare clientDataJSON
  const clientData = {
    type: 'webauthn.get',
    challenge: Buffer.from(challenge).toString('base64url'),
    origin: 'https://localhost:3000',
    crossOrigin: false,
  };
  const clientDataJSON = Buffer.from(JSON.stringify(clientData));

  // Step 3: Hash the clientDataJSON
  const clientDataHash = crypto.createHash('sha256').update(clientDataJSON).digest();

  // Step 4: Prepare authenticatorData
  const rpIdHash = crypto.createHash('sha256').update('localhost').digest();
  const flags = Buffer.from([0x01]); // User Present flag
  const signCount = Buffer.alloc(4); // 32-bit signature counter
  const authenticatorData = Buffer.concat([rpIdHash, flags, signCount]);

  // Step 5: Concatenate authenticatorData and clientDataHash
  const dataToSign = Buffer.concat([authenticatorData, clientDataHash]);

  // Step 6: Sign the concatenated data
  const signature = crypto.createSign('SHA256').update(dataToSign).sign(privateKey);

  // Step 7: Assemble the response
  return {
    clientDataJSON: clientDataJSON.toString(),
    authenticatorData: authenticatorData,
    signature: signature,
    userHandle: null,
  };
};
