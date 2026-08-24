import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

/**
 * Port 4402 keeps clear of the sample dApp (4400 stock, 4401 byo) and the wallet origin (5173),
 * so the whole demo stack can run at once. `--host` is what lets `portless` publish it as
 * http://paymaster-admin.localhost alongside the other origins.
 */
export default defineConfig({
  plugins: [react()],
  server: { port: 4402 },
  build: { sourcemap: true },
});
