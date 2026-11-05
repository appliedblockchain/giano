import { GianoError, type GianoErrorOptions } from "../../giano-error";

/** Why the wallet-api session ended on this device. */
export type SessionEndReason =
	/** wallet-api refused the session (401): idle, expired, capped out or revoked elsewhere. */
	| "unauthorized"
	/** The user signed out of this device. */
	| "logout"
	/** The user signed out of every device. */
	| "logout-all";

/**
 * Thrown when wallet-api refuses the session a request carried (G5). By then the client has
 * already dropped the token: the session cannot come back, and the user has to sign in again
 * with a passkey. `code` is EIP-1193's 4100 "Unauthorized", so a dApp can tell it apart from a
 * user rejection (4001).
 */
export class SessionEndedError extends GianoError {
	readonly code = 4100 as const;

	constructor(
		message = "the wallet session ended — sign in again",
		options?: GianoErrorOptions,
	) {
		super(message, options);
	}
}

/**
 * True when `error`, or anything in its `cause` chain, is a SessionEndedError. viem wraps the
 * errors its hooks and transports throw, so the original is often a few causes down.
 */
export function isSessionEndedError(error: unknown): boolean {
	let current: unknown = error;
	for (let depth = 0; current && depth < 10; depth++) {
		if (current instanceof SessionEndedError) return true;
		current = (current as { cause?: unknown }).cause;
	}
	return false;
}
