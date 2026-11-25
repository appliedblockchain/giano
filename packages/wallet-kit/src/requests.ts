import { isSessionEndedError } from "@appliedblockchain/giano-wallet-core";
import {
	RPC_ERRORS,
	TransportRpcError,
} from "@appliedblockchain/giano-wallet-transport";
import type { WalletRuntime } from "./runtimes";

/** A dApp request awaiting user consent in the popup UI. */
export type PendingRequest = {
	/** 'manage' opens the wallet-management view (WM-54); it resolves when the user closes it. */
	kind: "connect" | "transaction" | "sign" | "manage";
	method: string;
	params: unknown;
	dappOrigin: string;
	/** The chain this session negotiated — named on every consent screen (MC-80, MC-81). */
	chainId: number;
	chainName: string;
	/** The per-chain runtime serving this session (sponsorship pre-flight and all). */
	runtime: WalletRuntime;
	/**
	 * For 'connect' only: what approving signs in with when there is no session, and the other
	 * choice the screen may offer. See {@link ConnectOffer}.
	 */
	connect?: ConnectOffer;
	approve: () => void;
	/** For a 'connect' whose offer has an alternative: approves with that choice instead. */
	approveAlternative?: () => void;
	reject: () => void;
	/**
	 * Answers the dApp that the wallet session ended (EIP-1193 4100), not that the user refused
	 * (4001): wallet-api refused the session while the request was on screen (G5).
	 */
	sessionEnded: () => void;
};

/**
 * How a connect signs in, so the screen can label its buttons.
 * - `session`: this device is signed in; approving continues with the session's passkey. No alternative.
 * - `held-passkey`: this device is known to hold a passkey; approving signs in with whichever one the
 *   browser offers (any user, any wallet it belongs to). The alternative creates a new wallet.
 * - `default`: nothing is known; approving signs in with this device's stored user's passkeys, or
 *   creates a wallet when it has none. The alternative signs in with a passkey the device holds.
 */
export type ConnectOffer =
	| { primary: "session" }
	| { primary: "held-passkey"; alternative: "new-wallet" }
	| { primary: "default"; alternative: "held-passkey" };

/** Which button the user pressed on a consent screen. */
export type ConsentDecision = "primary" | "alternative";

type Listener = (pending: PendingRequest | null) => void;

/**
 * Single-slot consent queue (WK-10): the popup shows one request at a time; approval runs the
 * request through the Giano provider, rejection answers 4001 without touching it. A second
 * request while one is pending is refused rather than queued silently.
 */
export function createRequestStore() {
	let current: PendingRequest | null = null;
	const listeners = new Set<Listener>();

	const notify = () => {
		for (const listener of listeners) listener(current);
	};

	return {
		get current(): PendingRequest | null {
			return current;
		},
		subscribe(listener: Listener): () => void {
			listeners.add(listener);
			listener(current);
			return () => listeners.delete(listener);
		},
		/** Resolves with the user's decision; the caller performs the actual request. */
		requestConsent(
			input: Omit<
				PendingRequest,
				"approve" | "approveAlternative" | "reject" | "sessionEnded"
			>,
		): Promise<ConsentDecision> {
			if (current) {
				return Promise.reject(
					new TransportRpcError(
						RPC_ERRORS.INTERNAL,
						"another request is already pending",
					),
				);
			}
			return new Promise<ConsentDecision>((resolve, reject) => {
				const decide = (decision: ConsentDecision) => {
					current = null;
					notify();
					resolve(decision);
				};
				const hasAlternative =
					input.connect !== undefined && input.connect.primary !== "session";
				current = {
					...input,
					approve: () => decide("primary"),
					...(hasAlternative
						? { approveAlternative: () => decide("alternative") }
						: {}),
					reject: () => {
						current = null;
						notify();
						// A refusal is EIP-1193 4001, always (WK-09).
						reject(
							new TransportRpcError(
								RPC_ERRORS.USER_REJECTED,
								"User rejected the request",
							),
						);
					},
					sessionEnded: () => {
						current = null;
						notify();
						reject(
							new TransportRpcError(
								RPC_ERRORS.UNAUTHORIZED,
								"Wallet session ended — sign in again",
							),
						);
					},
				};
				notify();
			});
		},
	};
}

export type RequestStore = ReturnType<typeof createRequestStore>;

/**
 * True when wallet-api refused the session somewhere under `error`: wallet-core's
 * SessionEndedError, or an HTTP 401 that viem reports from the bundler transport (as a status
 * and a URL, rather than rethrowing what the transport saw), when that URL is wallet-api's. A
 * 401 from anywhere else (a bundler dialled directly, refusing a missing API key) is that
 * service's error, not the end of the session.
 */
function isSessionRefusal(
	error: unknown,
	isWalletApiUrl: (url: string) => boolean,
): boolean {
	if (isSessionEndedError(error)) return true;
	let current: unknown = error;
	for (let depth = 0; current && depth < 10; depth++) {
		const { status, url } = current as { status?: unknown; url?: unknown };
		if (status === 401 && typeof url === "string" && isWalletApiUrl(url))
			return true;
		current = (current as { cause?: unknown }).cause;
	}
	return false;
}

/**
 * Maps WebAuthn/user-abort failures to 4001, a refused session to 4100, and everything else
 * to an internal RPC error. `isWalletApiUrl` (the injection's) tells wallet-api's own 401s
 * from anyone else's; without it, only a SessionEndedError reads as a refused session.
 */
export function toRpcError(
	error: unknown,
	isWalletApiUrl: (url: string) => boolean = () => false,
): TransportRpcError {
	if (error instanceof TransportRpcError) return error;
	// G5: the session ended (idle, expired or revoked). 4100, not 4001: the user did not refuse
	// anything, and the dApp should send them back through connect.
	if (isSessionRefusal(error, isWalletApiUrl)) {
		return new TransportRpcError(
			RPC_ERRORS.UNAUTHORIZED,
			"Wallet session ended — sign in again",
		);
	}
	const name = (error as { name?: string })?.name;
	const message = error instanceof Error ? error.message : "request failed";
	if (name === "NotAllowedError" || name === "AbortError") {
		return new TransportRpcError(
			RPC_ERRORS.USER_REJECTED,
			"User cancelled the passkey ceremony",
		);
	}
	// The account couldn't be (re)established — the popup was reopened and the persisted
	// session is gone/expired. Surface a clean EIP-1193 disconnect so the dApp reconnects.
	if (/not connected/i.test(message)) {
		return new TransportRpcError(
			RPC_ERRORS.DISCONNECTED,
			"Wallet session expired — reconnect",
		);
	}
	return new TransportRpcError(RPC_ERRORS.INTERNAL, message);
}
