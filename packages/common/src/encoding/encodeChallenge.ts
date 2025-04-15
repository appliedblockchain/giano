import { ECDSASigValue } from '@peculiar/asn1-ecc';
import { AsnParser } from '@peculiar/asn1-schema';
import { BytesLike, ethers } from 'ethers';
import { uint8ArrayToUint256 } from './numbers';

const N = BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551')
const HALF_N = N / 2n;

export function encodeChallenge(credentialId: BytesLike | null, assertionResponse: AuthenticatorAssertionResponse) {
  const decodedClientDataJson = new TextDecoder().decode(assertionResponse.clientDataJSON);
  const responseTypeLocation = decodedClientDataJson.indexOf('"type":');
  const challengeLocation = decodedClientDataJson.indexOf('"challenge":');
  const parsedSignature = AsnParser.parse(assertionResponse.signature, ECDSASigValue);
  
  const s = uint8ArrayToUint256(parsedSignature.s);
  
  // Normalize s to the lower value to prevent signature malleability
  const normalizedS = s > HALF_N ? (N - s) : s;

  // Convert r and s to 32-byte hex strings
  const rHex = ethers.toBeHex(ethers.hexlify(new Uint8Array(parsedSignature.r)), 32);
  const sHex = ethers.toBeHex(normalizedS, 32); // Convert BigInt to 32-byte hex

  return ethers.AbiCoder.defaultAbiCoder().encode(
    [
      `tuple(${credentialId ? 'bytes credentialId, ': ''}bytes authenticatorData, string clientDataJSON, uint256 challengeLocation, uint256 responseTypeLocation, bytes32 r, bytes32 s)`,
    ],
    [
      [
        credentialId,
        new Uint8Array(assertionResponse.authenticatorData),
        decodedClientDataJson,
        challengeLocation,
        responseTypeLocation,
        rHex,
        sHex,
      ].filter(v => !!v),
    ],
  );
}
