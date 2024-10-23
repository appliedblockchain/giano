import { deepMerge, publicKey as defaultPublicKey } from "./defaults/publicKey";


/**
 * Credential client for web
 * create a client for the navigator.credentials API using the publicKey as parameter
 * returns create and get credentials using the navigator.credentials API
 * 
 * @param publicKey 
 * @returns {
 * getCredential: (id?: BufferSource, challenge?: BufferSource) => Promise<any>;
 * createCredential: (username: string, challenge?: BufferSource) => Promise<any>;
 * }
 */
export const credentialClient = (pk: Partial<PublicKeyCredentialCreationOptions> = {}) => {
  // deep merge the default publicKey with the publicKey passed as parameter
  const publicKey = deepMerge(defaultPublicKey, pk);

  const getCredential = async (id?: BufferSource, challenge?: BufferSource) => {
    const params = {
        challenge: challenge ?? publicKey.challenge,
        rpId: publicKey.rp.id,
        userVerification: 'preferred',
        ...(id && {
            allowCredentials: [
                {
                    id: id,
                    type: 'public-key' as string,
                },
            ],
        }),
    } as PublicKeyCredentialRequestOptions;
    return (await window.navigator.credentials.get({
        publicKey: params,
    })) as PublicKeyCredential & { response: AuthenticatorAssertionResponse };
  };

  const createCredential = async (username: string, challenge?: BufferSource) => {
      const credential = (await navigator.credentials.create({
        publicKey: {
          ...publicKey,
          challenge: challenge ?? publicKey.challenge,
          user: {
            id: new TextEncoder().encode(username),
            displayName: username,
            name: username,
          }
        }
      })) as PublicKeyCredential & { response: AuthenticatorAttestationResponse };
      return credential;
  }

  return {
    getCredential,
    createCredential
  }
}

export const { getCredential, createCredential } = credentialClient({
  rp: {
    id: window.location.hostname,
    name: 'Giano',
  },
});
