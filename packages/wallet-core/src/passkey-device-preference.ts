import type {
	createWebAuthnCredential,
	toWebAuthnAccount,
} from "viem/account-abstraction";
/** A browser UI suggestion, never an authenticator eligibility policy. */
export type PasskeyDevicePreference = "browser-default" | "prefer-mobile";

export function resolvePasskeyDevicePreference(
	value: unknown,
): PasskeyDevicePreference {
	if (value === undefined || value === "browser-default")
		return "browser-default";
	if (value === "prefer-mobile") return value;
	throw new Error(
		"passkeyDevicePreference must be 'browser-default' or 'prefer-mobile'",
	);
}

/** Preserve the challenge, RP, verification and credential eligibility verbatim. */
export function withPasskeyDevicePreference<T extends { publicKey?: object }>(
	options: T,
	preference?: PasskeyDevicePreference,
): T {
	if (resolvePasskeyDevicePreference(preference) === "browser-default") {
		return options;
	}
	return options.publicKey
		? { ...options, publicKey: { ...options.publicKey, hints: ["hybrid"] } }
		: options;
}

/** Resolve the browser function lazily: constructing/restoring an account raises no prompt. */
export function passkeyCredentialGet(
	preference?: PasskeyDevicePreference,
): Parameters<typeof toWebAuthnAccount>[0]["getFn"] {
	if (resolvePasskeyDevicePreference(preference) === "browser-default") {
		return undefined;
	}
	return (options) =>
		navigator.credentials.get(
			withPasskeyDevicePreference(
				options ?? {},
				preference,
			) as CredentialRequestOptions,
		);
}

export function passkeyCredentialCreate(
	preference?: PasskeyDevicePreference,
): Parameters<typeof createWebAuthnCredential>[0]["createFn"] {
	if (resolvePasskeyDevicePreference(preference) === "browser-default") {
		return undefined;
	}
	return (options) =>
		navigator.credentials.create(
			withPasskeyDevicePreference(
				options ?? {},
				preference,
			) as CredentialCreationOptions,
		);
}
