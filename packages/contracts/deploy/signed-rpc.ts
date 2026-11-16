/**
 * A viem HTTP transport that signs every request for a Silent Data RPC (the custom-rpc gateway).
 *
 * The gateway replaces `from` with a random address on an unsigned `eth_call` or `eth_estimateGas`,
 * and keeps it only when the request is signed by `from`. It verifies an EIP-191 signature over
 * `chainId + body + timestamp`, where `body` is the exact HTTP body. So this transport signs the body
 * viem is about to send, and adds:
 * - `x-timestamp`: RFC 3339, within the gateway's window;
 * - `x-signature`: EIP-191 signature of `chainId + body + timestamp`;
 * - with a delegate, `x-delegate` (the ticket as JSON) and `x-delegate-signature` (the root key's
 *   EIP-191 signature of `chainId + ticket JSON`). The caller obtains that signature and passes it in;
 *   the payload is then signed by the delegate (ephemeral) key.
 *
 * Matches silent-data-rollup-providers core `Base.ts` (`prepareMessage`, `signAuthHeader`,
 * `generateDelegateHeaders`) and the custom-rpc's `signatures.go` for an EOA signer. Smart-wallet
 * signers (`x-signer-swc`) are not covered.
 */
import { type Hex, type HttpTransport, http, type LocalAccount } from "viem";

/** A delegate ticket, exactly as the gateway reads it from `x-delegate`. */
export type DelegateTicket = {
	/** RFC 3339; the gateway refuses a ticket that expires more than 12 hours ahead. */
	expires: string;
	ephemeralAddress: `0x${string}`;
};

export type SignedRpcOptions = {
	chainId: number;
	/** Signs each request: the root key, or the delegate's ephemeral key when `delegate` is set. */
	signer: Pick<LocalAccount, "signMessage">;
	delegate?: {
		ticket: DelegateTicket;
		/** The root key's EIP-191 signature of `${chainId}${JSON.stringify(ticket)}`. */
		signature: Hex;
	};
};

/** The message the root key signs to authorise a delegate ticket. */
export function delegateTicketMessage(
	chainId: number,
	ticket: DelegateTicket,
): string {
	return `${chainId}${JSON.stringify(ticket)}`;
}

export function signedHttp(
	url: string,
	options: SignedRpcOptions,
): HttpTransport {
	const { chainId, signer, delegate } = options;
	const delegateHeaders: Record<string, string> = delegate
		? {
				"x-delegate": JSON.stringify(delegate.ticket),
				"x-delegate-signature": delegate.signature,
			}
		: {};
	return http(url, {
		async fetchFn(input, init) {
			const body = typeof init?.body === "string" ? init.body : "";
			const timestamp = new Date().toISOString();
			const signature = await signer.signMessage({
				message: `${chainId}${body}${timestamp}`,
			});
			const headers = new Headers(init?.headers);
			headers.set("x-timestamp", timestamp);
			headers.set("x-signature", signature);
			for (const [name, value] of Object.entries(delegateHeaders))
				headers.set(name, value);
			return fetch(input, { ...init, headers });
		},
	});
}
