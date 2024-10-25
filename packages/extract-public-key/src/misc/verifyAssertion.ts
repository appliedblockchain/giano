import * as helpers from './helpers.js';

type PublicKeyEncoded = string;
type ChallengeEncoded = string;

type AssertionEncoded = {
  id: string;
  rawId: string;
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
  };
};

type AssertionResponse = {
  clientDataJSON: ArrayBuffer;
  authenticatorData: ArrayBuffer;
  signature: ArrayBuffer;
};

type ClientData = {
  type: string;
  challenge: string;
  origin: string;
};

const verifyAssertion = async (
  assertion: AssertionEncoded,
  expectedChallenge: ChallengeEncoded,
  expectedRpId: string,
  allowedOrigins: string[],
  publicKey: PublicKeyEncoded,
): Promise<boolean> => {
  const assertionResponse = assertion.response;

  const clientData = JSON.parse(helpers.bufferToByteString(helpers.base64URLToBuffer(assertionResponse.clientDataJSON))) as ClientData;

  if (clientData.type !== 'webauthn.get') throw new Error("Failed to verify 'clientData.type'");
  if (atob(clientData.challenge) !== expectedChallenge) throw new Error("Failed to verify 'clientData.challenge'");
  if (!allowedOrigins.includes(clientData.origin)) throw new Error("Failed to verify 'clientData.origin");

  const authenticatorData = helpers.base64URLToBuffer(assertionResponse.authenticatorData);
  if (authenticatorData.byteLength < 37) throw new Error("Malformed 'authData'");
  const rpIdHash = authenticatorData.slice(0, 32);
  const rpIdData = new TextEncoder().encode(expectedRpId);
  const expectedRpIdHash = new Uint8Array(await crypto.subtle.digest('SHA-256', rpIdData));
  if (!helpers.areBytewiseEqual(rpIdHash, expectedRpIdHash)) throw new Error("Failed to verify 'rpId' hash");

  const flagsBits = authenticatorData[32]?.toString(2) ?? '';
  if (flagsBits.charAt(flagsBits.length - 1) !== '1') throw new Error('Failed to verify user present flag');

  const signature = helpers.convertDERSignatureToECDSASignature(helpers.base64URLToBuffer(assertionResponse.signature));
  const clientDataHash = new Uint8Array(await crypto.subtle.digest('SHA-256', helpers.base64URLToBuffer(assertionResponse.clientDataJSON)));
  const data = helpers.concatenateBuffers(authenticatorData, clientDataHash);

  const verifiedSignature = await crypto.subtle.verify(
    {
      name: 'ECDSA',
      hash: 'SHA-256',
    },
    await crypto.subtle.importKey(
      'spki',
      helpers.base64URLToBuffer(publicKey),
      {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
      true,
      ['verify'],
    ),
    signature,
    data,
  );

  return verifiedSignature;
};

export default verifyAssertion;
