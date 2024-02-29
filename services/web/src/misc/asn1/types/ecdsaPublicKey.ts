import { AsnProp, AsnPropTypes } from '@peculiar/asn1-schema';
import { ECDSAPublicKeyDetais } from './ecdsaPublicKeyDetails';

export class ECDSAPublicKey {
  @AsnProp({ type: ECDSAPublicKeyDetais })
  public publicKeyDetails = new ECDSAPublicKeyDetais();

  @AsnProp({ type: AsnPropTypes.BitString })
  public publicKey = new ArrayBuffer(0);
}
