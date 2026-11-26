import type { PendingRequest } from "@appliedblockchain/giano-wallet-kit";

/**
 * The connect consent. With a session it continues with that session's passkey. Without one, it
 * says what "Continue with passkey" does on this device and offers the other choice: a device known
 * to hold a passkey signs in with whichever one the browser offers, and can still create a new
 * wallet; a device that never signed in here creates one, and can still use a passkey it holds (one
 * added from another device, or synced from a password manager).
 */
export function Connect({ request }: { request: PendingRequest }) {
	const primary = request.connect?.primary ?? "default";
	return (
		<>
			<div className="origin-banner">
				Connection request from
				<b>{request.dappOrigin}</b>
			</div>
			<div className="card">
				<h2>Connect your Giano wallet</h2>
				{/* The chain the dApp asked for and was granted — named on every consent screen (MC-80). */}
				<div className="kv">
					<span className="k">Network</span>
					<span className="v" data-testid="consent-chain">
						{request.chainName}
					</span>
				</div>
				<p data-testid="connect-explanation">
					{primary === "session"
						? "Continue with the passkey you are signed in with. This app only receives your wallet address."
						: primary === "held-passkey"
							? "Sign in with a passkey this device holds — your browser lists them. The passkey never leaves your authenticator, and this app only receives your wallet address."
							: "Continue with your passkey. If you don't have a wallet on this device yet, one is created for you — the passkey never leaves your authenticator, and this app only receives your wallet address."}
				</p>
			</div>
			<div className="actions">
				<button type="button" className="danger" onClick={request.reject}>
					Cancel
				</button>
				{request.approveAlternative ? (
					<button
						type="button"
						onClick={request.approveAlternative}
						data-testid={
							primary === "held-passkey"
								? "connect-new-wallet"
								: "connect-existing-passkey"
						}
					>
						{primary === "held-passkey"
							? "Create a new wallet"
							: "Use a passkey I already have"}
					</button>
				) : null}
				<button type="button" className="primary" onClick={request.approve}>
					Continue with passkey
				</button>
			</div>
		</>
	);
}
