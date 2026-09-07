import { decodeFunctionData, erc20Abi, formatEther, type Hex } from 'viem';
import { gianoSmartWalletAbi } from '@appliedblockchain/giano-contracts';
import type { PendingRequest } from '../requests';

type TxRequest = { to?: Hex; value?: Hex | bigint; data?: Hex };

function describeCallData(data: Hex | undefined): string | null {
  if (!data || data === '0x') return null;
  for (const abi of [erc20Abi, gianoSmartWalletAbi] as const) {
    try {
      const decoded = decodeFunctionData({ abi, data });
      return `${decoded.functionName}(${(decoded.args as readonly unknown[] | undefined)?.map((a) => String(a)).join(', ') ?? ''})`;
    } catch {
      // try next abi
    }
  }
  return null;
}

export function ReviewTransaction({ request }: { request: PendingRequest }) {
  const [tx] = (request.params as [TxRequest] | undefined) ?? [{}];
  const value = tx.value !== undefined ? BigInt(tx.value) : 0n;
  const decoded = describeCallData(tx.data);

  return (
    <>
      <div className="origin-banner">
        Transaction request from
        <b>{request.dappOrigin}</b>
      </div>
      <div className="card">
        <h2>Review transaction</h2>
        <div className="kv">
          <span className="k">To</span>
          <span className="v">{tx.to ?? '—'}</span>
        </div>
        <div className="kv">
          <span className="k">Value</span>
          <span className="v">{formatEther(value)} ETH</span>
        </div>
        {decoded ? (
          <div className="kv">
            <span className="k">Call</span>
            <span className="v">{decoded}</span>
          </div>
        ) : null}
        {tx.data && tx.data !== '0x' ? <div className="data-box">{tx.data}</div> : null}
        <p>Approving signs this transaction with your passkey and submits it through the wallet service.</p>
      </div>
      <div className="actions">
        <button className="danger" onClick={request.reject}>
          Reject
        </button>
        <button className="primary" onClick={request.approve}>
          Approve
        </button>
      </div>
    </>
  );
}
