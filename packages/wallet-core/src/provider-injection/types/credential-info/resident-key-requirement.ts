const possibleValues: string[] = [
  'discouraged',
  'preferred',
  'required',
] satisfies ResidentKeyRequirement[]

const allowedValuesMessage = possibleValues.map(v => `'${v}'`).join(', ')

export function assertResidentKeyRequirement(
  value: unknown,
  options?: { descriptor?: string }
): asserts value is ResidentKeyRequirement {
  if (typeof value === 'string' && possibleValues.includes(value)) {
    return
  }

  const errorMessage = options?.descriptor
    ? `${options.descriptor} must be one of the following literals: ${allowedValuesMessage}`
    : `Resident Key Requirement must be one of the following literals: ${allowedValuesMessage}`

  throw new Error(errorMessage)
}
