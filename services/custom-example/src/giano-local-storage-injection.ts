import type { GianoProviderInjection, ChainType } from '@appliedblockchain/giano-connector'

function hexToBytes(hex: string) {
  hex = hex.replace(/^0x/g, '')
  if (hex.length % 2 !== 0) {
    hex = '0' + hex
  }
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16)
  }
  return bytes
}

function concatBytes(bytes: Uint8Array[]) {
  const totalLength = bytes.reduce((acc, curr) => acc + curr.length, 0)
  const result = new Uint8Array(totalLength)
  let offset = 0
  for (const byte of bytes) {
    result.set(byte, offset)
    offset += byte.length
  }
  return result
}

function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')
}

function padBytes(bytes: Uint8Array, size: number) {
  if (bytes.length < size) {
    return concatBytes([new Uint8Array(size - bytes.length).fill(0), bytes])
  }
  return bytes
}

export const gianoLocalStorageInjection: GianoProviderInjection = {
  getNameForCredential: async () => {
    return 'Giano Passkey'
  },
  getCredentialId: async () => {
    const passkeyIdBase64 = localStorage.getItem('gpk-passkey-id')

    if (!passkeyIdBase64) {
      return null
    }

    return new Uint8Array(Buffer.from(passkeyIdBase64, 'base64'))
  },
  getChallenge: async () => {
    const challenge = new Uint8Array(32)

    return crypto.getRandomValues(challenge)
  },
  onCredentialCreated: async (credentialName, challenge, credential) => {
    const passkeyIdBase64 = Buffer.from(credential.rawId).toString('base64')

    localStorage.setItem('gpk-passkey-id', passkeyIdBase64)

    return null // proceed to create a smart wallet
  },
  encodeUserId: (
    id: string,
    gianoSmartWalletFactoryAddress: string,
    chainId: string,
    chainType: ChainType,
  ) => {
    return concatBytes([
      padBytes(hexToBytes(id), 16),
      padBytes(hexToBytes(gianoSmartWalletFactoryAddress), 20),
      padBytes(hexToBytes(chainId), 4),
      padBytes(hexToBytes(chainType.toString(16)), 1),
    ])
  },
  decodeUserId: (userId: Uint8Array) => {
    const userIdSlice = userId.slice(0, 16)
    const walletFactoryAddress = userId.slice(16, 36)
    const chainId = userId.slice(36, 40)
    const chainType = userId.slice(40, 41)
    return {
      userId: [
        bytesToHex(userIdSlice.slice(0, 4)),
        bytesToHex(userIdSlice.slice(4, 6)),
        bytesToHex(userIdSlice.slice(6, 8)),
        bytesToHex(userIdSlice.slice(8, 10)),
        bytesToHex(userIdSlice.slice(10)),
      ].join('-'),
      walletFactoryAddress: '0x' + bytesToHex(walletFactoryAddress),
      chainId: parseInt(bytesToHex(chainId), 16),
      chainType: parseInt(bytesToHex(chainType), 16) as ChainType,
    }
  },
  onCredentialSignedIn: async (credential) => {
    console.log('Credential signed in', { credential })
    return true
  }
}
