
import { Passkey, type PasskeyCreateRequest } from 'react-native-passkey';
import { deepMerge, publicKey as defaultPublicKey } from './defaults/publicKey.js';

/**
 * create a client for the Passkey API using the publicKey as parameter
 * returns create and get credentials using the Passkey API
 * 
 * 
 * @require install the react-native-passkey package
 * yarn add react-native-passkey
 * or
 * npm install react-native-passkey --save
 * then
 * npx pod-install
 * 
 * @example
 * import { credentialClient } from '@giano/rn-credential';
import { getCredential } from '../../../services/web/src/client/common/credentials';
 * const { getCredential, createCredential } = credentialClient({
 *    rp: {
 *      id: 'teamId.and.your.bundle.id',
 *      name: 'Giano',
 *   },
 * });
 * 
 * @param pk partial publicKey
 * @returns {
 * getCredential: (id?: string, challenge?: string) => Promise<any>;
 * createCredential: (username: string, challenge?: string) => Promise<any>;
 * }
 */



export const credentialClient = (pk: Partial<PasskeyCreateRequest>) => {
    const publicKey = deepMerge(defaultPublicKey, pk);
    const getCredential = async (username?: string, challenge?: string) => {
        const requestJson = {
            'challenge': challenge ?? publicKey.challenge,
            'timeout': publicKey.timeout,
            'userVerification': publicKey.authenticatorSelection.userVerification,
            'rpId': publicKey.rp.id,
        };
        return Passkey.get(requestJson);
    }
    const createCredential = async (username: string, challenge?: string) => {
        const requestJson = {
            ...publicKey,
            'challenge': challenge ?? publicKey.challenge,
            'user': {
                id: username,
                displayName: username,
                name: username,
            }
        };
        return Passkey.create(requestJson);
    }

    return {
        getCredential,
        createCredential
    }
}

export const { getCredential, createCredential } = credentialClient({
    challenge: 'abc',
    rp: {
        id: 'your.bundle.id',
        name: 'Giano',
    },
});
