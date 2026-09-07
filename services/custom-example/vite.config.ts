import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// The sample dApp runs on http://app.localhost:4400 — an origin already allow-listed
// by the e2e wallet stack (wallet-web GIANO_ALLOWED_DAPP_ORIGINS + wallet-api CORS_ORIGINS),
// so it works against `deploy/docker-compose.e2e.yml` unmodified. No COOP header is set,
// so the wallet popup keeps `window.opener` access (required by the transport).
export default defineConfig({
  plugins: [react()],
  server: { port: 4400 },
  build: { sourcemap: true },
});
