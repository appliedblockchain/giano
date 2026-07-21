// `optional` is the WebAuthn default for a user-initiated assertion: it lets the browser
// prompt (passkey chooser / user verification). `silent` is wrong here — it means "return a
// credential only without any user mediation", which is impossible for a UV-required passkey:
// Chromium quietly resolves null, and Firefox throws `Unsupported credential mediation requirement`.
export const DEFAULT_CREDENTIAL_MEDIATION_REQUIREMENT = 'optional' satisfies CredentialMediationRequirement
export const DEFAULT_RESIDENT_KEY_REQUIREMENT = 'preferred' satisfies ResidentKeyRequirement
export const DEFAULT_USER_VERIFICATION_REQUIREMENT = 'required' satisfies UserVerificationRequirement
