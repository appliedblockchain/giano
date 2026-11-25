/**
 * Names the passkey provider from the AAGUID a passkey's authenticator reports at registration, so the
 * wallet can show where each passkey is stored (PS-1).
 *
 * A short, hand-kept list of the providers users are most likely to hold. An AAGUID is a public
 * identifier that each provider publishes; these values match the community list at
 * github.com/passkeydeveloper/passkey-authenticator-aaguids. That list carries no licence, so it is
 * not vendored. An AAGUID not listed here, or the all-zero AAGUID some authenticators report, yields
 * null: the wallet then shows only whether the passkey is synced.
 *
 * Display only. Never an input to authorisation or matching: an authenticator chooses its own AAGUID,
 * and with attestation "none" nothing proves it.
 */
const PROVIDERS: Readonly<Record<string, string>> = {
	"ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4": "Google Password Manager",
	"fbfc3007-154e-4ecc-8c0b-6e020557d7bd": "Apple Passwords",
	"dd4ec289-e01d-41c9-bb89-70fa845d4bf2": "iCloud Keychain (Managed)",
	"adce0002-35bc-c60a-648b-0b25f1f05503": "Chrome on Mac",
	"771b48fd-d3d4-4f74-9232-fc157ab0507a": "Edge on Mac",
	"08987058-cadc-4b81-b6e1-30de50dcbe96": "Windows Hello",
	"9ddd1817-af5a-4672-a2b9-3e3dd95000a9": "Windows Hello",
	"6028b017-b1d4-4c02-b4b3-afcdafc96bb2": "Windows Hello",
	"d3452668-01fd-4c12-926c-83a4204853aa": "Microsoft Password Manager",
	"53414d53-554e-4700-0000-000000000000": "Samsung Pass",
	"bada5566-a7aa-401f-bd96-45619a55120d": "1Password",
	"d548826e-79b4-db40-a3d8-11116f7e8349": "Bitwarden",
	"531126d6-e717-415c-9320-3d9aa6981239": "Dashlane",
	"b78a0a55-6ef8-d246-a042-ba0f6d55050c": "LastPass",
	"b84e4048-15dc-4dd0-8640-f4f60813c8af": "NordPass",
	"50726f74-6f6e-5061-7373-50726f746f6e": "Proton Pass",
	"f3809540-7f14-49c1-a8b3-8f813b225541": "Enpass",
	"fdb141b2-5d84-443e-8a35-4698c205a502": "KeePassXC",
};

/** The provider's name for an AAGUID, or null when it is unknown, absent or all zeros. */
export function passkeyProviderName(
	aaguid: string | null | undefined,
): string | null {
	if (!aaguid) return null;
	return PROVIDERS[aaguid.toLowerCase()] ?? null;
}
