/**
 * Signs RPC requests for a Silent Data RPC (the custom-rpc gateway).
 *
 * The gateway replaces `from` with a random address on an unsigned `eth_call` or `eth_estimateGas`,
 * and keeps it only when the request is signed by `from`. It verifies an EIP-191 signature over
 * `chainId + body + timestamp`, where `body` is the exact HTTP body. Each signed request carries:
 * - `x-timestamp`: RFC 3339, within the gateway's window;
 * - `x-signature`: EIP-191 signature of `chainId + body + timestamp`.
 *
 * Matches silent-data-rollup-providers core `Base.ts` (`prepareMessage`, `signAuthHeader`) and the
 * custom-rpc's `signatures.ts` for an EOA signer. Delegates (`x-delegate`) and smart-wallet signers
 * (`x-signer-swc`) are not covered.
 *
 * `signatureHeaders` is the one implementation of the scheme: `signedHttp` (viem) and
 * provision-paymaster.ts (ethers) both use it.
 */
import { type HttpTransport, type HttpTransportConfig, http } from "viem";

/** Signs an EIP-191 message: a viem account's or an ethers wallet's `signMessage`. */
export type SignMessage = (message: string) => Promise<string>;

/**
 * The headers that sign one request. `body` must be the exact HTTP body as a string: anything else
 * is refused, because a request signed over other bytes would reach the RPC unsigned in effect.
 */
export async function signatureHeaders(
	chainId: number,
	body: unknown,
	signMessage: SignMessage,
): Promise<{ "x-timestamp": string; "x-signature": string }> {
	if (typeof body !== "string")
		throw new Error(
			`cannot sign an RPC request whose body is not a string (${body === null ? "null" : typeof body})`,
		);
	const timestamp = new Date().toISOString();
	return {
		"x-timestamp": timestamp,
		"x-signature": await signMessage(`${chainId}${body}${timestamp}`),
	};
}

/** A viem HTTP transport that signs every request with `signer` (see the module comment). */
export function signedHttp(
	url: string,
	options: {
		chainId: number;
		signer: { signMessage(args: { message: string }): Promise<string> };
	},
	config: Omit<HttpTransportConfig, "fetchFn"> = {},
): HttpTransport {
	const { chainId, signer } = options;
	return http(url, {
		...config,
		async fetchFn(input, init) {
			const headers = new Headers(init?.headers);
			const signature = await signatureHeaders(chainId, init?.body, (message) =>
				signer.signMessage({ message }),
			);
			for (const [name, value] of Object.entries(signature))
				headers.set(name, value);
			return fetch(input, { ...init, headers });
		},
	});
}
