// Giano accepts only 'required': wallet-api and the wallet contract both reject a passkey response
// without the UV flag (G4), so asking for less would only turn a clear client-side refusal into a
// server-side or on-chain one.
const possibleValues: string[] = [
	"required",
] satisfies UserVerificationRequirement[];

const allowedValuesMessage = possibleValues.map((v) => `'${v}'`).join(", ");

export function assertUserVerificationRequirement(
	value: unknown,
	options?: { descriptor?: string },
): asserts value is "required" {
	if (typeof value === "string" && possibleValues.includes(value)) {
		return;
	}

	const errorMessage = options?.descriptor
		? `${options.descriptor} must be one of the following literals: ${allowedValuesMessage} (Giano requires user verification)`
		: `User Verification Requirement must be one of the following literals: ${allowedValuesMessage} (Giano requires user verification)`;

	throw new Error(errorMessage);
}
