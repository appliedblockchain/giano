import { useEffect, useState } from 'react';
import { decodeFunctionData, erc20Abi, formatEther, type Hex } from 'viem';
import { gianoSmartWalletAbi } from '@appliedblockchain/giano-contracts';
import type { PendingRequest } from '@appliedblockchain/giano-wallet-kit';
import { refusalCopy } from './sponsorship-copy';
import type { SponsorshipPreflight, WalletRuntime } from '@appliedblockchain/giano-wallet-kit';

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

export function ReviewTransaction({ request, runtime }: { request: PendingRequest; runtime: WalletRuntime }) {
  const [tx] = (request.params as [TxRequest] | undefined) ?? [{}];
  const value = tx.value !== undefined ? BigInt(tx.value) : 0n;
  const decoded = describeCallData(tx.data);

  /**
   * The gate. Nothing about approval is rendered until this resolves, because the whole point is
   * that a user is never asked for a fingerprint or a face scan for a transaction that cannot be
   * paid for.
   */
  const [preflight, setPreflight] = useState<SponsorshipPreflight | null>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setPreflight(null);

    void runtime
      .checkSponsorship(tx)
      .then((result) => {
        if (cancelled) return;
        setPreflight(result);

        // Shown *and* logged. A transient banner is not enough: by the time a developer or a
        // support engineer is looking, the banner is long gone, and the reason is the only thing
        // that distinguishes "this app is misconfigured" from "this app is out of credit".
        if (result.state === 'refused') {
          console.error('[giano] sponsorship refused', {
            reason: result.reason,
            message: result.message,
            ruleResults: result.ruleResults,
            to: tx.to,
          });
        } else if (result.state === 'unavailable') {
          console.error('[giano] sponsorship unavailable', { message: result.message, to: tx.to });
        } else if (result.state === 'sponsored') {
          console.info('[giano] sponsorship available — this transaction’s fees are covered by the application');
        }
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        const message = error instanceof Error ? error.message : 'sponsorship check failed';
        console.error('[giano] sponsorship check failed', { message });
        setPreflight({ state: 'unavailable', message });
      });

    return () => {
      cancelled = true;
    };
    // `attempt` is what a retry increments; the transaction itself never changes for one request.
  }, [runtime, tx.to, tx.data, tx.value, attempt]);

  return (
    <>
      <div className="origin-banner">
        Transaction request from
        <b>{request.dappOrigin}</b>
      </div>
      <div className="card">
        <h2>Review transaction</h2>
        {/* Which chain this lands on is material to the decision (MC-80, D10). */}
        <div className="kv">
          <span className="k">Network</span>
          <span className="v" data-testid="consent-chain">{request.chainName}</span>
        </div>
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
        {preflight?.state === 'sponsored' ? (
          <p data-testid="sponsorship-covered">
            This application covers the network fee for this transaction. Approving signs it with your passkey and
            submits it through the wallet service.
          </p>
        ) : null}
        {preflight?.state === 'not-applicable' ? (
          <p>Approving signs this transaction with your passkey and submits it through the wallet service.</p>
        ) : null}
      </div>

      {preflight === null ? (
        <div className="status" data-testid="sponsorship-checking">
          <span className="spinner" /> Checking whether this transaction’s fee is covered…
        </div>
      ) : null}

      {preflight?.state === 'refused' || preflight?.state === 'unavailable' ? (
        <SponsorshipRefusal preflight={preflight} onRetry={() => setAttempt((n) => n + 1)} />
      ) : null}

      <div className="actions">
        <button className="danger" onClick={request.reject}>
          {preflight?.state === 'refused' || preflight?.state === 'unavailable' ? 'Close' : 'Reject'}
        </button>
        {/*
          No approve button until the pre-flight says this transaction can actually be paid for.
          Offering one and failing afterwards would mean asking for a passkey ceremony that could
          never have succeeded.
        */}
        {preflight?.state === 'sponsored' || preflight?.state === 'not-applicable' ? (
          <button className="primary" onClick={request.approve}>
            Approve
          </button>
        ) : null}
      </div>
    </>
  );
}

function SponsorshipRefusal({ preflight, onRetry }: { preflight: SponsorshipPreflight; onRetry: () => void }) {
  const copy =
    preflight.state === 'refused'
      ? refusalCopy(preflight.reason)
      : refusalCopy('temporarily-unavailable');
  const reason = preflight.state === 'refused' ? preflight.reason : 'temporarily-unavailable';

  return (
    <div className="card" data-testid="sponsorship-refusal" data-reason={reason}>
      <h2>{copy.title}</h2>
      <p>{copy.body}</p>
      {/*
        Always present, never conditional: the user cannot resolve any of these themselves, so a
        refusal that does not say who can leaves them retrying something that will never work.
      */}
      <p data-testid="sponsorship-refusal-action">{copy.action}</p>
      {copy.retryable ? (
        <button className="primary" onClick={onRetry} data-testid="sponsorship-retry">
          Try again
        </button>
      ) : null}
    </div>
  );
}
