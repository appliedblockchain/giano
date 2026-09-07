import { hexToString, isHex } from 'viem';
import type { PendingRequest } from '../requests';

function renderPayload(request: PendingRequest): { title: string; body: string; domainChainId?: number } {
  const params = (request.params as unknown[]) ?? [];
  if (request.method === 'eth_signTypedData_v4') {
    const [, typedData] = params as [string, string];
    try {
      const parsed = typeof typedData === 'string' ? JSON.parse(typedData) : typedData;
      const domainChainId = typeof parsed?.domain?.chainId === 'number' ? parsed.domain.chainId : undefined;
      return { title: 'Sign typed data', body: JSON.stringify(parsed, null, 2), domainChainId };
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
  const { title, body, domainChainId } = renderPayload(request);
  // MC-82: where the typed-data domain carries its own chain and it differs from the
  // session's, the mismatch is SHOWN rather than silently accepted. A warning, not a
  // refusal: signing a message scoped to another chain is a legitimate thing to do
  // deliberately and an alarming thing to do unknowingly.
  const chainMismatch = domainChainId !== undefined && domainChainId !== request.chainId;
  return (
    <>
      <div className="origin-banner">
        Signature request from
        <b>{request.dappOrigin}</b>
      </div>
      <div className="card">
        <h2>{title}</h2>
        <div className="kv">
          <span className="k">Network</span>
          <span className="v" data-testid="consent-chain">{request.chainName}</span>
        </div>
        <div className="data-box" data-testid="sign-payload">{body}</div>
        {chainMismatch ? (
          <div className="error" data-testid="chain-mismatch-warning">
            This message declares chain {domainChainId}, but this session is connected to {request.chainName} (chain{' '}
            {request.chainId}). Only sign if you meant to sign for that other chain.
          </div>
        ) : null}
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
