import type { GianoProviderInjection } from '@appliedblockchain/giano-connector'

export const gianoLocalStorageInjection: GianoProviderInjection = {
  getNameForCredential: async () => {
    return 'Giano Passkey'
  },
  getCredentialId: async () => {
    const passkeyIdBase64 = localStorage.getItem('gpk-passkey-id')

    if (!passkeyIdBase64) {
      console.log('No passkey id found')
      return null
    }
    console.log('Passkey id found', { passkeyIdBase64 })

    return new Uint8Array(Buffer.from(passkeyIdBase64, 'base64'))
  },
  getChallenge: async () => {
    const challenge = new Uint8Array(32)

    return crypto.getRandomValues(challenge)
  },
  onCredentialCreated: async (credentialName, challenge, credential) => {
    const passkeyIdBase64 = Buffer.from(credential.rawId).toString('base64')

    localStorage.setItem('gpk-passkey-id', passkeyIdBase64)
    console.log('Passkey created', { credentialName, passkeyIdBase64 })

    return null // proceed to create a smart wallet
  },
}
