import { useEffect, useMemo, useState } from 'react';
import type { WalletConfig } from './config';
import { createWalletHost } from './host';
import type { PendingRequest } from './requests';
import { createWalletRuntime } from './wallet';
import { Connect } from './views/Connect';
import { ReviewTransaction } from './views/ReviewTransaction';
import { Settings } from './views/Settings';
import { SignMessage } from './views/SignMessage';

const WALLET_VERSION = import.meta.env.VITE_WALLET_VERSION ?? '0.1.0';

export function App({ config }: { config: WalletConfig }) {
  const runtime = useMemo(() => createWalletRuntime(config), [config]);
  const host = useMemo(() => createWalletHost(runtime, config, WALLET_VERSION), [runtime, config]);
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
      {pending?.kind === 'transaction' ? <ReviewTransaction request={withProcessing(pending)} runtime={runtime} /> : null}
      {pending?.kind === 'sign' ? <SignMessage request={withProcessing(pending)} /> : null}

      {!pending && processing ? (
        <div className="status">
          <span className="spinner" /> Follow your browser's passkey prompt, then return to the app…
        </div>
      ) : null}

      {!pending && !processing && isPopup ? (
        <div className="status">Waiting for a request from {host.getDappOrigin() ?? 'the application'}…</div>
      ) : null}

      {!pending && !processing && !isPopup ? <Settings runtime={runtime} config={config} /> : null}
    </div>
  );
}
