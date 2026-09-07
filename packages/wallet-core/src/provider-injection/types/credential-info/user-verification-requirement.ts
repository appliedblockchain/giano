const possibleValues: string[] = [
  'discouraged',
  'preferred',
  'required',
] satisfies UserVerificationRequirement[]

const allowedValuesMessage = possibleValues.map(v => `'${v}'`).join(', ')

export function assertUserVerificationRequirement(
  value: unknown,
  options?: { descriptor?: string }
): asserts value is UserVerificationRequirement {
  if (typeof value === 'string' && possibleValues.includes(value)) {
    return
  }

  const errorMessage = options?.descriptor
    ? `${options.descriptor} must be one of the following literals: ${allowedValuesMessage}`
    : `User Verification Requirement must be one of the following literals: ${allowedValuesMessage}`

  throw new Error(errorMessage)
}
