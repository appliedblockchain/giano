import { ECDSASigValue } from '@peculiar/asn1-ecc';
import { AsnParser } from '@peculiar/asn1-schema';
import { ethers } from 'ethers';
import { uint8ArrayToUint256 } from './numbers';

export function encodeChallenge(pubKey: {x: string, y: string}, assertionResponse: AuthenticatorAssertionResponse) {
  const decodedClientDataJson = new TextDecoder().decode(assertionResponse.clientDataJSON);
  const responseTypeLocation = decodedClientDataJson.indexOf('"type":');
  const challengeLocation = decodedClientDataJson.indexOf('"challenge":');
  const parsedSignature = AsnParser.parse(assertionResponse.signature, ECDSASigValue);

  return ethers.AbiCoder.defaultAbiCoder().encode(
    [
      'tuple(bytes authenticatorData, string clientDataJSON, uint256 challengeLocation, uint256 responseTypeLocation, uint256 r, uint256 s,tuple(uint256 x, uint256 y))',
    ],
    [
      [
        new Uint8Array(assertionResponse.authenticatorData),
        decodedClientDataJson,
        challengeLocation,
        responseTypeLocation,
        uint8ArrayToUint256(parsedSignature.r),
        uint8ArrayToUint256(parsedSignature.s),
        [pubKey.x, pubKey.y],
      ],
    ],
  );
}
