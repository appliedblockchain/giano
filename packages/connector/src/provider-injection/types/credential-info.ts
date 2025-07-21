import { isNonEmptyBufferSource } from './buffer-source'

export type CredentialInfo = {
  credentialId?: BufferSource | null
  challenge: BufferSource
}

export function assertCredentialInfo(info: unknown): asserts info is CredentialInfo {
  if (typeof info !== 'object' || info === null) {
    throw new Error('Credential info must be an object')
  }

  const { credentialId, challenge } = info as CredentialInfo

  if (
    credentialId !== null &&
    credentialId !== undefined &&
    !isNonEmptyBufferSource(credentialId)
  ) {
    throw new Error('`credentialId` must be null, undefined, or a non-empty BufferSource')
  }

  if (!isNonEmptyBufferSource(challenge)) {
    throw new Error('`challenge` must be a non-empty BufferSource')
  }
}
