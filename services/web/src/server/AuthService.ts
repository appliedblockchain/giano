import database from './database';

export default class AuthService {
  // https://simplewebauthn.dev/docs/packages/server#additional-data-structures
  static async saveUser(username: string, data: any) {
    const id = data.id;
    const public_key = data.publicKey;
    const cose_alg = data.coseAlg;
    const transports = data.transports ? JSON.stringify(data.transports) : null;

    await database('authenticators').insert({
      username,
      id,
      public_key,
      cose_alg,
      transports,
    });

    return AuthService.getUser(username);
  }

  static async getUser(username: string) {
    const result = await database('authenticators').select().where({ username }).first();
    if (!result) return null;

    result.transports = result.transports ? JSON.parse(result.transports) : null;
    return result;
  }
}
