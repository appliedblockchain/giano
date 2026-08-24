import { hexToString, isHex } from 'viem';
import type { PendingRequest } from '../requests';

function renderPayload(request: PendingRequest): { title: string; body: string } {
  const params = (request.params as unknown[]) ?? [];
  if (request.method === 'eth_signTypedData_v4') {
    const [, typedData] = params as [string, string];
    try {
      return { title: 'Sign typed data', body: JSON.stringify(typeof typedData === 'string' ? JSON.parse(typedData) : typedData, null, 2) };
    } catch {
      return { title: 'Sign typed data', body: String(typedData) };
    }
  }
  // personal_sign: [message, address]; eth_sign: [address, message]
  const raw = request.method === 'personal_sign' ? params[0] : params[1];
  if (typeof raw === 'string' && isHex(raw)) {
    try {
      return { title: 'Sign message', body: hexToString(raw) };
    } catch {
      return { title: 'Sign message', body: raw };
    }
  }
  return { title: 'Sign message', body: String(raw) };
}

export function SignMessage({ request }: { request: PendingRequest }) {
  const { title, body } = renderPayload(request);
  return (
    <>
      <div className="origin-banner">
        Signature request from
        <b>{request.dappOrigin}</b>
      </div>
      <div className="card">
        <h2>{title}</h2>
        <div className="data-box" data-testid="sign-payload">{body}</div>
        <p>Only sign if you trust this application. Signatures are replay-safe: they bind to your wallet and chain.</p>
      </div>
      <div className="actions">
        <button className="danger" onClick={request.reject}>
          Reject
        </button>
        <button className="primary" onClick={request.approve}>
          Sign
        </button>
      </div>
    </>
  );
}
