import { assertNonEmptyBufferSource } from '../buffer-source'
import { assertCredentialMediationRequirement } from './credential-mediation-requirement'
import { assertUserVerificationRequirement } from './user-verification-requirement'

// JSDocs links
import {
  DEFAULT_CREDENTIAL_MEDIATION_REQUIREMENT, // `BaseCredentialInfo.mediation`
  DEFAULT_USER_VERIFICATION_REQUIREMENT, // `BaseCredentialInfo.userVerification`
} from './defaults'

export type BaseCredentialInfo = {
  /**
   * When not provided, defaults to {@link DEFAULT_USER_VERIFICATION_REQUIREMENT}
   */
  userVerification?: UserVerificationRequirement
  /**
   * When not provided, defaults to {@link DEFAULT_CREDENTIAL_MEDIATION_REQUIREMENT}
   */
  mediation?: CredentialMediationRequirement
  challenge: BufferSource
}

export function assertBaseCredentialInfo(info: unknown): asserts info is BaseCredentialInfo {
  if (typeof info !== 'object' || info === null) {
    throw new Error('Credential info must be an object')
  }

  const {
    userVerification,
    mediation,
    challenge,
  } = info as BaseCredentialInfo

  if (userVerification !== undefined) {
    assertUserVerificationRequirement(userVerification, {
      descriptor: 'userVerification',
    })
  }

  if (mediation !== undefined) {
    assertCredentialMediationRequirement(mediation, {
      descriptor: 'mediation',
    })
  }

  assertNonEmptyBufferSource(challenge, { descriptor: 'challenge' })
}
