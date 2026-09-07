import { isNonEmptyBufferSource } from '../buffer-source'
import { assertBaseCredentialInfo, BaseCredentialInfo } from './base-credential-info'
import { assertResidentKeyRequirement } from './resident-key-requirement'

// JSDocs links
import {
  DEFAULT_RESIDENT_KEY_REQUIREMENT, // `CredentialInfoCreate.residentKey`
} from './defaults'

export type CredentialInfoUse = BaseCredentialInfo & {
  credentialId: BufferSource | BufferSource[]
}
export type CredentialInfoCreate = BaseCredentialInfo & {
  credentialId: null
  /**
   * When not provided, defaults to {@link DEFAULT_RESIDENT_KEY_REQUIREMENT}
   */
  residentKey?: ResidentKeyRequirement
}
export type CredentialInfoUserPick = BaseCredentialInfo & {
  credentialId: 'user-pick'
}
export type CredentialInfo = (
  | CredentialInfoUse
  | CredentialInfoCreate
  | CredentialInfoUserPick
)

export function assertCredentialInfo(value: unknown): asserts value is CredentialInfo {
  if (typeof value !== 'object' || value === null) {
    throw new Error('Credential info must be an object')
  }

  assertBaseCredentialInfo(value)

  const info = value as CredentialInfo
  const { credentialId } = info

  if (credentialId === null) {
    if (info.residentKey !== undefined) {
      assertResidentKeyRequirement(info.residentKey, { descriptor: 'residentKey' })
    }
    return
  }

  if (
    credentialId === 'user-pick' ||
    isNonEmptyBufferSource(credentialId) ||
    ( // array of non-empty BufferSource items
      credentialId instanceof Array &&
      credentialId.every(x => isNonEmptyBufferSource(x))
    )
  ) {
    return
  }

  throw new Error('`credentialId` must be one of: `\'user-pick\'`, `null`, non-empty `BufferSource`, or an array of non-empty `BufferSource`')
}
