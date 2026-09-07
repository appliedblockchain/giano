import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { Provider } from './components/ui/provider';
import { Toaster } from './components/ui/toaster';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Provider forcedTheme="light">
      <App />
      <Toaster />
    </Provider>
  </StrictMode>,
);
