import { AsnProp, AsnPropTypes } from '@peculiar/asn1-schema';

export class ECDSAPublicKeyDetais {
  @AsnProp({ type: AsnPropTypes.ObjectIdentifier })
  public type = '';

  @AsnProp({ type: AsnPropTypes.ObjectIdentifier })
  public namedCurve = '';

  constructor(params: Partial<ECDSAPublicKeyDetais> = {}) {
    Object.assign(this, params);
  }
}
