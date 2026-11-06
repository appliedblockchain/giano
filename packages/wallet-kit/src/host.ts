import {
	RPC_ERRORS,
	TransportHost,
	TransportRpcError,
} from "@appliedblockchain/giano-wallet-transport";
import type { WalletConfig } from "./config";
import { type ConnectionGrants, createConnectionGrants } from "./grants";
import { createRequestStore, type RequestStore, toRpcError } from "./requests";
import type { WalletRuntime, WalletRuntimes } from "./runtimes";
import { checkSelfCall, OPERATION_METHODS } from "./self-calls";

const CONSENT_METHODS = new Set([
	"eth_sendTransaction",
	"personal_sign",
	"eth_sign",
	"eth_signTypedData_v4",
	"eth_signUserOperation",
	"signed_eth_call",
]);
/** Methods that use the account, and so need the origin's connection grant (WK-34). */
const ACCOUNT_METHODS = new Set([
	...CONSENT_METHODS,
	"eth_prepareUserOperation",
	"eth_sendSignedUserOperation",
]);
/**
 * Provider methods the host calls for itself and never accepts from an application (WK-34):
 * `giano_restoreAccount` rebuilds the account with no prompt, so a dApp that could call it would
 * learn the address without connecting.
 */
const INTERNAL_METHODS = new Set(["giano_restoreAccount"]);
/** Provider events relayed to the dApp. */
const RELAYED_EVENTS = [
	"accountsChanged",
	"chainChanged",
	"disconnect",
] as const;

export type WalletHost = {
	/** Attach transport listeners and announce readiness to the opener. */
	start: () => void;
	stop: () => void;
	/** The single-slot pending-request queue, as subscribable state (WK-10). */
	requests: RequestStore;
	/** The pinned dApp origin, or null before the handshake. */
	readonly dappOrigin: string | null;
};

export type CreateWalletHostOptions = {
	runtimes: WalletRuntimes;
	config: WalletConfig;
	walletVersion: string;
};

type RequestContext = { dappOrigin: string; chainId: number };

/**
 * The transport-facing request handler, factored out of the host so the consent semantics are
 * testable without a live postMessage transport. Not part of the kit's public surface.
 */
export function createHostRequestHandler({
	runtimes,
	requests,
	grants,
	sendEvent,
}: {
	runtimes: WalletRuntimes;
	requests: RequestStore;
	grants: ConnectionGrants;
	/** Delivers a provider event to the dApp. */
	sendEvent?: (event: string, data: unknown) => void;
}) {
	// The origin this popup serves. The transport pins one origin per session, so the last
	// request's origin is the origin every relayed event goes to.
	let sessionOrigin: string | null = null;

	// WK-34: accountsChanged carries the address, so it reaches the dApp only while the origin
	// holds a grant. The check runs when the event fires, not when the relay is wired: the
	// management view can sign in (and emit the address) for an origin that never connected.
	// A first connect emits before its grant is recorded, so that event is dropped too; the
	// dApp learns the accounts from the eth_requestAccounts result.
	const relay = (event: string, data: unknown) => {
		if (
			event === "accountsChanged" &&
			!(sessionOrigin !== null && grants.has(sessionOrigin))
		) {
			return;
		}
		sendEvent?.(event, data);
	};

	// Event relay is wired per runtime, once, when a session first touches that chain.
	const wiredChains = new Set<number>();
	const runtimeForSession = (chainId: number): WalletRuntime => {
		const runtime = runtimes.runtimeFor(chainId);
		if (!wiredChains.has(chainId)) {
			wiredChains.add(chainId);
			for (const event of RELAYED_EVENTS) {
				runtime.provider.on(event, (data: unknown) => relay(event, data));
			}
		}
		return runtime;
	};

	return async (
		method: string,
		params: unknown,
		context: RequestContext,
	): Promise<unknown> => {
		sessionOrigin = context.dappOrigin;

		// MC-14/WK-11: chain switching is refused explicitly with EIP-1193 4200 — never silently
		// ignored, never answered by the read path, never appearing to succeed. A dApp that
		// wants another chain constructs a provider for it (D1).
		if (
			method === "wallet_switchEthereumChain" ||
			method === "wallet_addEthereumChain"
		) {
			throw new TransportRpcError(
				RPC_ERRORS.UNSUPPORTED_METHOD,
				"Giano binds one chain per session; connect a provider constructed for the target chain",
			);
		}

		if (INTERNAL_METHODS.has(method)) {
			throw new TransportRpcError(
				RPC_ERRORS.UNSUPPORTED_METHOD,
				`${method} is not available to applications`,
			);
		}

		// WK-34: the account is visible and usable only to an origin the user connected. These
		// checks run BEFORE the runtime is touched: a silent restore emits accountsChanged, and the
		// event relay would hand the address to the very origin being refused.
		const connected = grants.has(context.dappOrigin);
		if (!connected && method === "eth_accounts") {
			return [];
		}
		if (!connected && ACCOUNT_METHODS.has(method)) {
			throw new TransportRpcError(
				RPC_ERRORS.UNAUTHORIZED,
				"This application is not connected to the wallet; request eth_requestAccounts first",
			);
		}
		if (method === "wallet_revokePermissions") {
			try {
				grants.revoke(context.dappOrigin);
			} catch {
				// Never report a revoke the storage did not keep (WK-34).
				throw new TransportRpcError(
					RPC_ERRORS.INTERNAL,
					"The wallet could not save the revocation; try again",
				);
			}
		}

		const runtime = runtimeForSession(context.chainId);

		// WM-54/WM-55: the application's ONE management affordance — open the view. It
		// accepts no parameters (WM-39: nothing pre-filled, nothing preselected) and
		// returns nothing (WM-40: no owner set, no names, no outcome go back to the dApp).
		if (method === "giano_openWalletManagement") {
			const params_ = params as unknown[] | undefined;
			if (
				params_ !== undefined &&
				params_ !== null &&
				!(Array.isArray(params_) && params_.length === 0)
			) {
				throw new TransportRpcError(
					RPC_ERRORS.UNSUPPORTED_METHOD,
					"the management interface accepts no parameters from the application",
				);
			}
			await requests.requestConsent({
				kind: "manage",
				method,
				params: undefined,
				dappOrigin: context.dappOrigin,
				chainId: runtime.chainId,
				chainName: runtime.chainName,
				runtime,
			});
			return null;
		}

		const needsConsent =
			method === "eth_requestAccounts" || CONSENT_METHODS.has(method);
		// WK-12: a signing/tx request from a connected origin can land on a freshly (re)opened
		// popup whose in-memory account was lost when the previous popup closed. Silently
		// rebuild it from the persisted session before asking for consent — no extra passkey
		// prompt; the single ceremony still happens when the operation is actually signed. If
		// it can't be restored, the request fails with a disconnect error (from the self-call
		// check below for an operation, from the provider otherwise) and the dApp must
		// reconnect via eth_requestAccounts.
		if (ACCOUNT_METHODS.has(method) && !runtime.provider.getSmartAccount()) {
			await runtime.provider
				.request({ method: "giano_restoreAccount" } as never)
				.catch(() => undefined);
		}
		// A dApp must never get the account to call one of its own functions: that is how owners
		// are added or removed and how the account is upgraded. Refused before consent, so the
		// user is never shown an Approve button for one, and checked again after consent, because
		// the account can change while the user decides.
		const checked = assertNoSelfCall(runtime, method, params);
		if (checked) pinSender(method, params, checked);
		if (needsConsent) {
			await requests.requestConsent({
				kind:
					method === "eth_requestAccounts"
						? "connect"
						: method === "eth_sendTransaction"
							? "transaction"
							: "sign",
				method,
				params,
				dappOrigin: context.dappOrigin,
				// The chain is material to the decision the user is making, so every consent
				// screen names it (MC-80) — by name, not by number (MC-81).
				chainId: runtime.chainId,
				chainName: runtime.chainName,
				runtime,
			});
		}
		let forwarded = params;
		if (needsConsent) {
			const account = assertNoSelfCall(runtime, method, params);
			if (account) forwarded = pinSender(method, params, account);
		}
		let result: unknown;
		try {
			result = await runtime.provider.request({
				method,
				params: forwarded,
			} as never);
		} catch (error) {
			throw toRpcError(error, runtime.injection.isWalletApiUrl);
		}
		// The grant is recorded only once the user approved AND the account was established: a
		// cancelled passkey ceremony after the approval connects nothing.
		if (
			method === "eth_requestAccounts" &&
			Array.isArray(result) &&
			result.length > 0
		) {
			grants.grant(context.dappOrigin);
		}
		return result;
	};
}

/**
 * Refuses an operation request that would make the account call itself, or that cannot be
 * checked. A value-only transfer to self carries no calldata and stays allowed. The management
 * view builds its self-calls and calls the provider directly, so it does not pass through here.
 *
 * Returns the address of the account it checked against, for an operation method.
 *
 * Synchronous on purpose: the caller runs the provider request right after it, with no await
 * in between, so the request starts against the account that was checked.
 */
function assertNoSelfCall(
	runtime: WalletRuntime,
	method: string,
	params: unknown,
): string | undefined {
	if (!OPERATION_METHODS.has(method)) return undefined;
	const account = runtime.provider.getSmartAccount();
	// Without an account there is nothing to check against, so the request is refused here.
	// The provider would refuse it too; this is the error toRpcError gives for that case.
	if (!account) {
		throw new TransportRpcError(
			RPC_ERRORS.DISCONNECTED,
			"Wallet session expired — reconnect",
		);
	}
	const selfCall = checkSelfCall(method, params, account.address);
	if (selfCall === "self-call") {
		throw new TransportRpcError(
			RPC_ERRORS.UNAUTHORIZED,
			"an application cannot make the wallet call itself; use giano_openWalletManagement to let the user manage the wallet",
		);
	}
	if (selfCall === "unreadable") {
		throw new TransportRpcError(
			RPC_ERRORS.UNAUTHORIZED,
			"the request cannot be checked: params must be an array, the transaction or user operation must be an object, `to` and `data` must be hex strings, and a user operation's callData must be an execute or executeBatch call",
		);
	}
	return account.address;
}

/**
 * Binds a user operation to be signed to the account it was checked against. The provider
 * awaits before it signs, and it signs with whatever account it holds by then. It also refuses
 * a `sender` that is not that account. So with `sender` set to the checked account, a change of
 * account inside the provider makes it refuse the request instead of signing an unchecked one.
 *
 * A `sender` that is not the checked account is refused here, before consent. A missing one is
 * filled in. Other methods are returned unchanged: eth_sendSignedUserOperation already requires
 * `sender`, and the others build the operation from the account itself.
 */
function pinSender(method: string, params: unknown, account: string): unknown {
	if (method !== "eth_signUserOperation") return params;
	// assertNoSelfCall has already required an array whose first entry is an object.
	const [operation, ...rest] = params as [
		Record<string, unknown>,
		...unknown[],
	];
	const { sender } = operation;
	if (
		sender !== undefined &&
		(typeof sender !== "string" ||
			sender.toLowerCase() !== account.toLowerCase())
	) {
		throw new TransportRpcError(
			RPC_ERRORS.UNAUTHORIZED,
			"the user operation's sender is not the connected account",
		);
	}
	return [{ ...operation, sender: account }, ...rest];
}

/**
 * Wires the popup transport to the Giano provider with a consent gate (WK-08):
 * - eth_requestAccounts → a 'connect' request; approval records the origin's connection grant
 * - eth_sendTransaction → a 'transaction' request
 * - personal_sign / eth_sign / eth_signTypedData_v4 → a 'sign' request
 * - giano_openWalletManagement → a 'manage' request (resolves when the view closes)
 * - account methods from an origin with no grant → 4100; eth_accounts → [] (WK-34)
 * - giano_restoreAccount → refused; the host alone calls it (WK-34)
 * - accountsChanged → relayed only to an origin with a grant (WK-34)
 * - everything else (read paths) forwards straight to the provider
 * All signing and credential work happens HERE, on the wallet origin — the dApp only
 * ever sees postMessage RPC. The host is headless: it never renders consent, it awaits
 * the decision the UI raises through approve()/reject() (D7, WK-09).
 *
 * The chain is negotiated once per transport session, in the handshake (S1): every request
 * on the session is served by that chain's runtime, resolved lazily on first use (MC-44),
 * and there is no path by which a request reaches a different chain's runtime.
 */
export function createWalletHost({
	runtimes,
	config,
	walletVersion,
}: CreateWalletHostOptions): WalletHost {
	const requests = createRequestStore();

	let transport: TransportHost;
	const onRequest = createHostRequestHandler({
		runtimes,
		requests,
		grants: createConnectionGrants(),
		sendEvent: (event, data) => transport.sendEvent(event, data),
	});

	transport = new TransportHost({
		walletVersion,
		allowedOrigins: config.allowedDappOrigins,
		// The closed list the handshake negotiates against (MC-03): a dApp naming a chain
		// outside it is refused before any request — or passkey ceremony (MC-85) — happens.
		servedChainIds: [...runtimes.servedChainIds],
		onRequest,
	});

	return {
		start: () => transport.start(),
		stop: () => transport.stop(),
		requests,
		get dappOrigin() {
			return transport.dappOrigin;
		},
	};
}
