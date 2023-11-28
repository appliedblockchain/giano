import database from './database';
import * as helpers from './helpers';

export default class AuthService {
  // https://simplewebauthn.dev/docs/packages/server#additional-data-structures
  static async saveUser(username: string, data: any) {
    const id = data.id;
    const publicKey = data.publicKey;
    const coseAlg = data.coseAlg;
    const counter = data.counter;
    const credentialDeviceType = data.credentialDeviceType;
    const credentialBackedUp = data.credentialBackedUp;
    const transports = data.transports ? JSON.stringify(data.transports) : null;

    await database('authenticators').insert({
      username,
      id,
      publicKey,
      coseAlg,
      counter,
      credentialDeviceType,
      credentialBackedUp,
      transports,
    });

    return AuthService.getUser(username);
  }

  static async getUser(username: string) {
    const result = await database('authenticators').select().where({ username }).first();
    if (!result) return null;

    result.id = result.id;
    result.publicKey = result.publicKey; // helpers.base64URLToBuffer;
    result.transports = result.transports ? JSON.parse(result.transports) : null;
    return result;
  }
}
