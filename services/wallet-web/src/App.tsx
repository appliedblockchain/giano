import { useEffect, useMemo, useState } from 'react';
import type { WalletConfig } from './config';
import { createWalletHost } from './host';
import type { PendingRequest } from './requests';
import { createWalletRuntimes } from './wallet';
import { Connect } from './views/Connect';
import { Manage } from './views/Manage';
import { ReviewTransaction } from './views/ReviewTransaction';
import { SignMessage } from './views/SignMessage';

const WALLET_VERSION = import.meta.env.VITE_WALLET_VERSION ?? '0.1.0';

export function App({ config }: { config: WalletConfig }) {
  const runtimes = useMemo(() => createWalletRuntimes(config), [config]);
  const host = useMemo(() => createWalletHost(runtimes, config, WALLET_VERSION), [runtimes, config]);
  const [pending, setPending] = useState<PendingRequest | null>(null);
  const [processing, setProcessing] = useState(false);

  const isPopup = typeof window !== 'undefined' && !!window.opener;

  useEffect(() => {
    host.transport.start();
    const unsubscribe = host.requests.subscribe((request) => {
      setPending(request);
      if (request) setProcessing(false);
    });
    return () => {
      unsubscribe();
      host.transport.stop();
    };
  }, [host]);

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
      {pending?.kind === 'manage' ? <Manage runtimes={runtimes} config={config} onClose={pending.approve} /> : null}

      {!pending && processing ? (
        <div className="status">
          <span className="spinner" /> Follow your browser's passkey prompt, then return to the app…
        </div>
      ) : null}

      {!pending && !processing && isPopup ? (
        <div className="status">Waiting for a request from {host.getDappOrigin() ?? 'the application'}…</div>
      ) : null}

      {!pending && !processing && !isPopup ? <Manage runtimes={runtimes} config={config} /> : null}
    </div>
  );
}
