const possibleValues: string[] = [
  'conditional',
  'optional',
  'required',
  'silent',
] satisfies CredentialMediationRequirement[]

const allowedValuesMessage = possibleValues.map(v => `'${v}'`).join(', ')

export function assertCredentialMediationRequirement(
  value: unknown,
  options?: { descriptor?: string }
): asserts value is CredentialMediationRequirement {
  if (typeof value === 'string' && possibleValues.includes(value)) {
    return
  }

  const errorMessage = options?.descriptor
    ? `${options.descriptor} must be one of the following literals: ${allowedValuesMessage}`
    : `Credential Mediation Requirement must be one of the following literals: ${allowedValuesMessage}`

  throw new Error(errorMessage)
}
