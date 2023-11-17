import database from './database';
import * as helpers from './helpers';

export default class AuthService {
  // https://simplewebauthn.dev/docs/packages/server#additional-data-structures
  static async saveUser(username: string, data: any) {
    const credentialID = helpers.bufferToBase64URL(data.credentialID);
    const credentialPublicKey = helpers.bufferToBase64URL(data.credentialPublicKey);
    const counter = data.counter;
    const credentialDeviceType = data.credentialDeviceType;
    const credentialBackedUp = data.credentialBackedUp;
    const transports = data.transports ?? null;

    await database('authenticators').insert({
      username,
      credentialID,
      credentialPublicKey,
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

    result.credentialID = helpers.base64URLToBuffer(result.credentialID);
    result.credentialPublicKey = helpers.base64URLToBuffer(result.credentialPublicKey);
    return result;
  }
}
