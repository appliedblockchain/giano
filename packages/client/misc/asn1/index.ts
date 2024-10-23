import { ECDSASigValue } from '@peculiar/asn1-ecc';
import { AsnParser } from '@peculiar/asn1-schema';
import { base64URLToBuffer } from '../helpers';
import { ECDSAPublicKey } from './types/ecdsaPublicKey';

function shouldRemoveLeadingZero(bytes: Uint8Array): boolean {
  return bytes[0] === 0x0 && (bytes[1] & (1 << 7)) !== 0;
}

export const parsePublicKey = (publicKey: string) => {
  const parsedPublicKey = AsnParser.parse(base64URLToBuffer(publicKey), ECDSAPublicKey).publicKey;

  // remove the first byte (0x04)
  const publicKeyBuffer = parsedPublicKey.slice(1);

  // X and Y values
  const pubKeyX = publicKeyBuffer.slice(0, publicKeyBuffer.byteLength / 2);
  const pubKeyY = publicKeyBuffer.slice(publicKeyBuffer.byteLength / 2);

  return [new Uint8Array(pubKeyX), new Uint8Array(pubKeyY)];
};

export const parseSignature = (signature: string) => {
  const parsedSignature = AsnParser.parse(base64URLToBuffer(signature), ECDSASigValue);

  let rBytes = new Uint8Array(parsedSignature.r);
  let sBytes = new Uint8Array(parsedSignature.s);

  if (shouldRemoveLeadingZero(rBytes)) {
    console.log('removing leading zero from rBytes');
    rBytes = rBytes.slice(1);
  }

  if (shouldRemoveLeadingZero(sBytes)) {
    console.log('removing leading zero from sBytes');
    sBytes = sBytes.slice(1);
  }

  // r and s values
  return [rBytes, sBytes];
};
