import type { PendingRequest } from '../requests';

export function Connect({ request }: { request: PendingRequest }) {
  return (
    <>
      <div className="origin-banner">
        Connection request from
        <b>{request.dappOrigin}</b>
      </div>
      <div className="card">
        <h2>Connect your Giano wallet</h2>
        <p>
          Continue with your passkey. If you don't have a wallet on this device yet, one is created for you — the
          passkey never leaves your authenticator, and this app only receives your wallet address.
        </p>
      </div>
      <div className="actions">
        <button className="danger" onClick={request.reject}>
          Cancel
        </button>
        <button className="primary" onClick={request.approve}>
          Continue with passkey
        </button>
      </div>
    </>
  );
}
