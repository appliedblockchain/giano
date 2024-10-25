import { ECDSAPublicKeyDetais } from './ecdsaPublicKeyDetails.js';

export class ECDSAPublicKey {
  public publicKeyDetails = new ECDSAPublicKeyDetais();
  public publicKey = new ArrayBuffer(0);
}
