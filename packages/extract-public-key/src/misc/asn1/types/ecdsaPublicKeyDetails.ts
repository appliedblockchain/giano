
export class ECDSAPublicKeyDetais {
  public type = '';
  public namedCurve = '';
  constructor(params: Partial<ECDSAPublicKeyDetais> = {}) {
    Object.assign(this, params);
  }
}
