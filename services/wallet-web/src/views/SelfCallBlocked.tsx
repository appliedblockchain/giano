import {
	checkSelfCall,
	type PendingRequest,
} from "@appliedblockchain/giano-wallet-kit";

/**
 * Whether a consent screen must block this request: it would make the user's account call one
 * of its own functions, or its calls cannot be checked. The host already refuses both before
 * consent; the screens block them as a second layer. A value-only transfer to the account
 * carries no calldata and is not blocked.
 */
export function isSelfCallBlocked(request: PendingRequest): boolean {
	const account = request.runtime.provider.getSmartAccount();
	// No account means the host refuses the request after consent anyway.
	return (
		account !== null &&
		checkSelfCall(request.method, request.params, account.address) !== "none"
	);
}

/** The only screen a blocked request gets: no Approve or Sign button, only Close. */
export function SelfCallBlocked({
	request,
	bannerLabel,
}: {
	request: PendingRequest;
	bannerLabel: string;
}) {
	return (
		<>
			<div className="origin-banner">
				{bannerLabel}
				<b>{request.dappOrigin}</b>
			</div>

			<div className="card">
				<h2>Request blocked</h2>
				<div className="kv">
					<span className="k">Network</span>
					<span className="v" data-testid="consent-chain">
						{request.chainName}
					</span>
				</div>
				<div className="error" data-testid="self-call-blocked">
					This application asked your wallet to change its own settings, or sent
					a request the wallet cannot check. Such a change can add or remove the
					passkeys that control your wallet, or replace its code. An application
					cannot do this. Manage your wallet only from the wallet’s own
					management screen.
				</div>
			</div>

			<div className="actions">
				<button type="button" className="danger" onClick={request.reject}>
					Close
				</button>
			</div>
		</>
	);
}
