import { useEffect, useState } from 'react';
import { formatUnits, type Hex } from 'viem';
import type { PendingRequest, SponsorshipPreflight, TransactionDescription, UnknownReason, WalletRuntime } from '@appliedblockchain/giano-wallet-kit';
import { refusalCopy } from './sponsorship-copy';

type TxRequest = { to?: Hex; value?: Hex | bigint; data?: Hex };

/**
 * The transaction consent screen.
 *
 * Two things have to settle before an approve button exists, and both are gates for the same
 * reason: a user must not be asked for a passkey until they have seen what they are approving
 * and know it can be paid for.
 *
 *   1. The description — the runtime's human-readable account of the request, from the
 *      application's published mappings and the kit's built-ins. When it is `unknown`, the
 *      screen says so in so many words and shows the raw data, because raw data is the truth
 *      of last resort, not a default.
 *   2. The sponsorship pre-flight (WK-13…WK-15) — unchanged from before.
 */
export function ReviewTransaction({ request, runtime }: { request: PendingRequest; runtime: WalletRuntime }) {
  const [tx] = (request.params as [TxRequest] | undefined) ?? [{}];
  const nativeCurrency = runtime.nativeCurrency ?? { symbol: 'ETH', decimals: 18 };

  const [description, setDescription] = useState<TransactionDescription | null>(null);
  const [preflight, setPreflight] = useState<SponsorshipPreflight | null>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setDescription(null);
    setPreflight(null);

    // The runtime never rejects here, but a screen that could hang on a promise that did would
    // leave the user with no button at all — so the fallback is spelled out anyway.
    void runtime
      .describeTransaction(tx)
      .catch(
        (error: unknown): TransactionDescription => ({
          kind: 'unknown',
          reason: 'decode-failed',
          selector: tx.data && tx.data.length >= 10 ? tx.data.slice(0, 10) : null,
          contract: tx.to ?? null,
          warnings: [{ code: 'engine', message: error instanceof Error ? error.message : 'description failed' }],
          raw: { to: tx.to ?? null, value: typeof tx.value === 'bigint' ? `0x${tx.value.toString(16)}` : (tx.value ?? '0x0'), data: tx.data ?? '0x' },
        }),
      )
      .then((result) => {
        if (cancelled) return;
        setDescription(result);
        if (result.kind === 'unknown') {
          console.warn('[giano] transaction could not be described', { reason: result.reason, selector: result.selector, to: result.contract });
        } else if (result.warnings.length > 0) {
          console.info('[giano] transaction described with warnings', { source: result.source, warnings: result.warnings });
        }
      });

    void runtime
      .checkSponsorship(tx)
      .then((result) => {
        if (cancelled) return;
        setPreflight(result);

        // Shown *and* logged. A transient banner is not enough: by the time a developer or a
        // support engineer is looking, the banner is long gone, and the reason is the only thing
        // that distinguishes "this app is misconfigured" from "this app is out of credit".
        if (result.state === 'refused') {
          console.error('[giano] sponsorship refused', { reason: result.reason, message: result.message, ruleResults: result.ruleResults, to: tx.to });
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

  const payable = preflight?.state === 'sponsored' || preflight?.state === 'not-applicable';
  const refused = preflight?.state === 'refused' || preflight?.state === 'unavailable';

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

        {description === null ? (
          <div className="status" data-testid="tx-describing">
            <span className="spinner" /> Preparing the transaction summary…
          </div>
        ) : null}

        {description?.kind === 'described' ? <Described description={description} /> : null}

        {payable && description !== null ? (
          <p>
            {preflight?.state === 'sponsored' ? (
              <span data-testid="sponsorship-covered">
                This application covers the network fee for this transaction. Approving signs it with your passkey and
                submits it through the wallet service.
              </span>
            ) : (
              'Approving signs this transaction with your passkey and submits it through the wallet service.'
            )}
          </p>
        ) : null}
      </div>

      {description?.kind === 'unknown' ? <Unknown description={description} nativeCurrency={nativeCurrency} /> : null}

      {preflight === null ? (
        <div className="status" data-testid="sponsorship-checking">
          <span className="spinner" /> Checking whether this transaction’s fee is covered…
        </div>
      ) : null}

      {refused && preflight ? <SponsorshipRefusal preflight={preflight} onRetry={() => setAttempt((n) => n + 1)} /> : null}

      <div className="actions">
        <button className="danger" onClick={request.reject}>
          {refused ? 'Close' : 'Reject'}
        </button>
        {/*
          No approve button until BOTH the description has settled and the pre-flight says this
          transaction can actually be paid for. Offering one earlier would mean asking for a
          passkey ceremony for something the user has not seen, or that could never succeed.
        */}
        {payable && description !== null ? (
          <button className="primary" onClick={request.approve}>
            Approve
          </button>
        ) : null}
      </div>
    </>
  );
}

function Described({ description }: { description: Extract<TransactionDescription, { kind: 'described' }> }) {
  const generic = description.source === 'generic';
  const notes = description.warnings.filter((w) => w.code !== 'generic-interface' && w.code !== 'engine');
  const contractLabel = description.metadata?.contractName
    ? `${description.metadata.contractName} · ${shorten(description.contract)}`
    : shorten(description.contract);

  return (
    <>
      <p className="intent" data-testid="tx-intent" data-source={description.source}>
        {description.intent}
      </p>

      {description.fields.map((field, index) => (
        <div className="kv" key={`${field.label}-${index}`} data-testid="tx-field" data-label={field.label}>
          <span className="k">{field.label}</span>
          <span className="v" title={field.address}>
            {field.value}
          </span>
        </div>
      ))}

      {description.source !== 'native' ? (
        <div className="kv">
          <span className="k">Contract</span>
          <span className="v" title={description.contract}>
            {contractLabel}
          </span>
        </div>
      ) : null}

      {generic ? (
        <p className="note" data-testid="tx-generic-note">
          The wallet read this as a standard token action because the call has the shape of one. The application has not
          confirmed what this contract is, so check the contract address before approving.
        </p>
      ) : null}

      {notes.map((warning) => (
        <p className="note" key={warning.code} data-testid="tx-warning" data-code={warning.code}>
          {warningCopy(warning.code) ?? warning.message}
        </p>
      ))}

      {/* Everything above is the account the user acts on; this is the evidence, on demand (spec: MAY reveal). */}
      {description.source !== 'native' ? (
        <details className="technical">
          <summary>Technical details</summary>
          <div className="kv">
            <span className="k">Contract</span>
            <span className="v">{description.contract}</span>
          </div>
          <div className="kv">
            <span className="k">Function</span>
            <span className="v">{description.functionSignature}</span>
          </div>
          <div className="data-box">{description.raw.data}</div>
        </details>
      ) : null}
    </>
  );
}

function Unknown({
  description,
  nativeCurrency,
}: {
  description: Extract<TransactionDescription, { kind: 'unknown' }>;
  nativeCurrency: { symbol: string; decimals: number };
}) {
  let value = description.raw.value;
  try {
    value = `${formatUnits(BigInt(description.raw.value), nativeCurrency.decimals)} ${nativeCurrency.symbol}`;
  } catch {
    // shown as received
  }

  return (
    <div className="card warning-card" data-testid="tx-unknown" data-reason={description.reason}>
      <h2>This wallet cannot explain this transaction</h2>
      <p>{unknownCopy(description.reason)}</p>
      <p>
        Only approve it if you trust the application and expected exactly this action. What follows is the raw request, shown
        because nothing more readable is available.
      </p>
      {description.contract ? (
        <div className="kv">
          <span className="k">Contract</span>
          <span className="v">{description.contract}</span>
        </div>
      ) : null}
      {description.selector ? (
        <div className="kv">
          <span className="k">Function selector</span>
          <span className="v">{description.selector}</span>
        </div>
      ) : null}
      <div className="kv">
        <span className="k">Value</span>
        <span className="v">{value}</span>
      </div>
      <div className="data-box" data-testid="tx-raw">
        {description.raw.data}
      </div>
    </div>
  );
}

function unknownCopy(reason: UnknownReason): string {
  switch (reason) {
    case 'no-mapping':
      return 'The application has not published a description for this contract and function, so the wallet cannot tell you what it does.';
    case 'decode-failed':
      return 'The call data does not fit any function the wallet knows for this contract. It may be malformed, or built for a different contract.';
    case 'contract-creation':
      return 'This transaction deploys a new contract rather than calling an existing one.';
  }
}

function warningCopy(code: string): string | null {
  switch (code) {
    case 'token-unresolved':
      return 'The token’s symbol and decimals could not be read from the network, so the amount is shown as a raw number.';
    case 'mappings-unavailable':
      return 'The application’s own transaction descriptions could not be loaded; this summary uses only generic ones.';
    case 'interpolation-failed':
      return 'Part of the summary could not be filled in; check the fields below.';
    default:
      return null;
  }
}

function shorten(address: string): string {
  return `${address.slice(0, 6)}…${address.slice(-4)}`;
}

function SponsorshipRefusal({ preflight, onRetry }: { preflight: SponsorshipPreflight; onRetry: () => void }) {
  const copy = preflight.state === 'refused' ? refusalCopy(preflight.reason) : refusalCopy('temporarily-unavailable');
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
