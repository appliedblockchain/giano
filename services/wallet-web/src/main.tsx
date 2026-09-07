import { loadWalletConfig } from '@appliedblockchain/giano-wallet-kit';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import './styles.css';

const root = createRoot(document.getElementById('root')!);

// Runtime config: fetched from /config.json (rendered in the container at boot, MC-41).
// The kit validates it and fails fatally, naming the chain and field (WK-06); the
// production flag arms the test-paymaster guard (WK-05).
loadWalletConfig({ production: import.meta.env.PROD })
  .then((config) => {
    root.render(
      <StrictMode>
        <App config={config} />
      </StrictMode>,
    );
  })
  .catch((error: Error) => {
    root.render(<div className="shell">Wallet misconfigured: {error.message}</div>);
  });
