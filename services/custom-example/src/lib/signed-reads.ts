import {
	type Address,
	type Hex,
	type HttpTransport,
	http,
	keccak256,
	stringToBytes,
} from "viem";
import {
	generatePrivateKey,
	type PrivateKeyAccount,
	privateKeyToAccount,
} from "viem/accounts";

/**
 * Signed reads for a Silent Data RPC, for a Giano wallet (design D6 of the silent-data-network change).
 *
 * The RPC answers a read of private state only when the request is signed for the account that may
 * see it. A smart wallet cannot sign every request without a passkey prompt each time, so the wallet
 * approves a short-lived delegate key once, with `personal_sign`, and that key signs each read:
 *
 * 1. On the first read, a new ephemeral key is created in memory. It never leaves this module.
 * 2. The wallet approves the ticket `{ expires, ephemeralAddress }`: the dApp passes
 *    `keccak256(chainId + JSON(ticket))` to `personal_sign` as 0x hex, so the wallet signs those
 *    32 bytes. That is the one passkey prompt.
 * 3. Each read carries the wallet (`x-signer-swc`), the ticket and the wallet's approval
 *    (`x-delegate`, `x-delegate-signature`), and the ephemeral key's EIP-191 signature of
 *    `chainId + body + timestamp` (`x-timestamp`, `x-signature`). The RPC checks the approval with
 *    ERC-1271 on the wallet, and runs the call with `from` set to the wallet.
 *
 * Before the ticket expires, the next read asks the wallet for a new approval with a new key.
 *
 * Approve before you read: `await reader.approved()` from the click handler, then make the signed
 * request. The transport signs inside viem's `fetchFn`, which viem runs under the HTTP transport's
 * timeout (10 s by default). A passkey prompt there can outlast the timeout, and the read fails while
 * the wallet popup is still open. After `approved()`, the transport only signs in memory.
 */

/** A delegate ticket, exactly as the RPC reads it from `x-delegate`. The wallet signs this JSON, so key order matters. */
export type DelegateTicket = {
	/** RFC 3339. The RPC refuses a ticket that expires more than 12 hours ahead. */
	expires: string;
	ephemeralAddress: Address;
};

/** How long an approval lasts: one passkey prompt per hour of reading. */
export const DELEGATE_LIFETIME_MS = 60 * 60 * 1000;
/** A read this close to the expiry asks for a new approval first, so no read arrives with an expired ticket. */
export const DELEGATE_RENEW_MARGIN_MS = 60 * 1000;

/** The string the dApp passes to `personal_sign` to approve `ticket` (design D6, verified in task 4.1). */
export function delegateApprovalMessage(
	chainId: number,
	ticket: DelegateTicket,
): Hex {
	return keccak256(stringToBytes(`${chainId}${JSON.stringify(ticket)}`));
}

export type Delegate = {
	ticket: DelegateTicket;
	/** The wallet's `personal_sign` signature of {@link delegateApprovalMessage}. */
	approval: Hex;
	/** Milliseconds since the epoch, as `ticket.expires`. */
	expiresAt: number;
};

export type SignedReaderOptions = {
	chainId: number;
	/** The Giano wallet the reads are for. Its code must be deployed: the RPC checks the approval with ERC-1271. */
	wallet: Address;
	/**
	 * Asks the wallet to `personal_sign` the message, which approves `ticket`. `renewed` is true when
	 * an earlier approval expired.
	 */
	personalSign: (
		message: Hex,
		context: { ticket: DelegateTicket; renewed: boolean },
	) => Promise<Hex>;
	/** The clock, in milliseconds. Tests pass their own. */
	now?: () => number;
};

export class SignedReader {
	readonly chainId: number;
	readonly wallet: Address;
	private readonly personalSign: SignedReaderOptions["personalSign"];
	private readonly now: () => number;
	private current?: { delegate: Delegate; key: PrivateKeyAccount };
	private approving?: Promise<{ delegate: Delegate; key: PrivateKeyAccount }>;
	private approvals = 0;

	constructor(options: SignedReaderOptions) {
		this.chainId = options.chainId;
		this.wallet = options.wallet;
		this.personalSign = options.personalSign;
		this.now = options.now ?? Date.now;
	}

	/** The approved delegate, if one is valid now. Reading it never prompts. */
	get delegate(): Delegate | undefined {
		return this.isFresh() ? this.current?.delegate : undefined;
	}

	private isFresh(): boolean {
		return (
			this.current !== undefined &&
			this.current.delegate.expiresAt - DELEGATE_RENEW_MARGIN_MS > this.now()
		);
	}

	/**
	 * A valid delegate: the current one, or a new one after one `personal_sign` (the passkey prompt).
	 * Await it before each signed read, from the click handler, so the read itself never waits for the
	 * wallet. Concurrent calls share one prompt.
	 */
	async approved(): Promise<Delegate> {
		return (await this.fresh()).delegate;
	}

	/** The current delegate and its key, approved now if none is valid. Concurrent calls share one prompt. */
	private async fresh(): Promise<{
		delegate: Delegate;
		key: PrivateKeyAccount;
	}> {
		if (this.current && this.isFresh()) return this.current;
		if (!this.approving) {
			this.approving = this.approve().finally(() => {
				this.approving = undefined;
			});
		}
		return this.approving;
	}

	private async approve() {
		const key = privateKeyToAccount(generatePrivateKey());
		const expiresAt = this.now() + DELEGATE_LIFETIME_MS;
		const ticket: DelegateTicket = {
			expires: new Date(expiresAt).toISOString(),
			ephemeralAddress: key.address,
		};
		const approval = await this.personalSign(
			delegateApprovalMessage(this.chainId, ticket),
			{ ticket, renewed: this.approvals > 0 },
		);
		this.approvals += 1;
		this.current = { delegate: { ticket, approval, expiresAt }, key };
		return this.current;
	}

	/**
	 * The headers that sign `body`, the exact HTTP body of one JSON-RPC request. Without a valid
	 * delegate, it asks the wallet first: call {@link approved} before, so this only signs in memory.
	 */
	async headers(body: string): Promise<Record<string, string>> {
		const { delegate, key } = await this.fresh();
		const timestamp = new Date(this.now()).toISOString();
		return {
			"x-signer-swc": this.wallet,
			"x-signer-swc-type": "giano",
			"x-delegate": JSON.stringify(delegate.ticket),
			"x-delegate-signature": delegate.approval,
			"x-timestamp": timestamp,
			"x-signature": await key.signMessage({
				message: `${this.chainId}${body}${timestamp}`,
			}),
		};
	}

	/**
	 * A viem HTTP transport whose every request is signed for the wallet. Use it for private reads only.
	 *
	 * Await {@link approved} before each read. Without a valid delegate, the request still asks the
	 * wallet first, but inside viem's request timeout (10 s by default): a slow passkey prompt fails
	 * the read while the wallet popup is still open.
	 */
	transport(url: string): HttpTransport {
		return http(url, {
			// One read, one signed request: a retry would re-sign and could ask the wallet again.
			retryCount: 0,
			fetchFn: async (input, init) => {
				const body = typeof init?.body === "string" ? init.body : "";
				const headers = new Headers(init?.headers);
				for (const [name, value] of Object.entries(await this.headers(body)))
					headers.set(name, value);
				return fetch(input, { ...init, headers });
			},
		});
	}
}
