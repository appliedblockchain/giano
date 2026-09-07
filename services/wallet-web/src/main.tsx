import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { loadWalletConfig } from './config';
import './styles.css';

const root = createRoot(document.getElementById('root')!);

loadWalletConfig()
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
