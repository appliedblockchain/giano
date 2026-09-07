import type { PendingRequest, WalletConfig } from '@appliedblockchain/giano-wallet-kit';
import { usePendingRequest, useWalletKit, WalletHostProvider } from '@appliedblockchain/giano-wallet-kit/react';
import { useEffect, useState } from 'react';
import { Connect } from './views/Connect';
import { Manage } from './views/Manage';
import { ReviewTransaction } from './views/ReviewTransaction';
import { SignMessage } from './views/SignMessage';

const WALLET_VERSION = import.meta.env.VITE_WALLET_VERSION ?? '0.1.0';

/**
 * The stock wallet origin: the kit's runtimes and host behind Giano's own pixels. All of
 * the orchestration — per-chain runtimes, the consent gate, the management state machine —
 * lives in @appliedblockchain/giano-wallet-kit (WK-30); this tree only renders.
 */
export function App({ config }: { config: WalletConfig }) {
  return (
    <WalletHostProvider config={config} walletVersion={WALLET_VERSION}>
      <Popup config={config} />
    </WalletHostProvider>
  );
}

function Popup({ config }: { config: WalletConfig }) {
  const { host } = useWalletKit();
  const pending = usePendingRequest();
  const [processing, setProcessing] = useState(false);

  const isPopup = typeof window !== 'undefined' && !!window.opener;

  useEffect(() => {
    if (pending) setProcessing(false);
  }, [pending]);

  const withProcessing = (request: PendingRequest): PendingRequest => ({
    ...request,
    approve: () => {
      setProcessing(true);
      request.approve();
    },
  });

  return (
    <div className="shell">
      <div className="brand">
        {config.branding.name} <small>· secure wallet</small>
      </div>

      {pending?.kind === 'connect' ? <Connect request={withProcessing(pending)} /> : null}
      {pending?.kind === 'transaction' ? <ReviewTransaction request={withProcessing(pending)} runtime={pending.runtime} /> : null}
      {pending?.kind === 'sign' ? <SignMessage request={withProcessing(pending)} /> : null}
      {/* The management interface, opened by the application (WM-54). Closing it resolves
          the transport request with nothing (WM-40); the same view serves the standalone
          entry below, so the two entry points share one set of capabilities (WM-56). */}
      {pending?.kind === 'manage' ? <Manage onClose={pending.approve} /> : null}

      {!pending && processing ? (
        <div className="status">
          <span className="spinner" /> Follow your browser's passkey prompt, then return to the app…
        </div>
      ) : null}

      {!pending && !processing && isPopup ? (
        <div className="status">Waiting for a request from {host.dappOrigin ?? 'the application'}…</div>
      ) : null}

      {!pending && !processing && !isPopup ? <Manage /> : null}
    </div>
  );
}
