import { concatHex, toHex } from 'viem'
import { toWebAuthnAccount, WebAuthnAccount } from 'viem/account-abstraction'
import {
  CredentialInfoUse,
  CredentialInfoUserPick,
  GianoProviderInjection,
} from '../provider-injection'
import { getCredential } from './get-credential'

export const getWebAuthnAccount = async (
  options: CredentialInfoUse | CredentialInfoUserPick,
  injection: Pick<GianoProviderInjection,
    | 'onCredentialSignedIn'
    | 'getPublicKeyByCredentialId'
  >,
): Promise<WebAuthnAccount | null> => {
  try {
    const credential = await getCredential(options)
    if (!credential) {
      return null
    }

    const signInSuccess = await injection.onCredentialSignedIn(credential)
    if (!signInSuccess) {
      throw new Error('Failed to sign in with credential')
    }

    const { x, y } = await injection.getPublicKeyByCredentialId(credential.rawId)
    if (x === toHex(0, { size: 32 })) {
      throw new Error('Unknown credential ID')
    }

    return toWebAuthnAccount({
      credential: {
        id: credential.id,
        publicKey: concatHex([x, y]),
      },
    })
  } catch (error) {
    if (['NotAllowedError', 'AbortError'].includes((error as Error).name)) {
      return null
    }
    throw error
  }
}
