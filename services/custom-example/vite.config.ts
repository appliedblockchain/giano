import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// The sample dApp is reached at http://app.localhost — an origin already allow-listed by the
// e2e wallet stack (wallet-web GIANO_ALLOWED_DAPP_ORIGINS + wallet-api CORS_ORIGINS), so it
// works against `deploy/docker-compose.e2e.yml` unmodified. Port 4400 below is not the address
// anyone types: it is the loopback target portless publishes as http://app.localhost (the same
// route the e2e dApp fixture uses — they are alternatives, so they share it). Bring the routes
// up with `pnpm -F @appliedblockchain/giano-e2e portless:up`. No COOP header is set, so the
// wallet popup keeps `window.opener` access (required by the transport).
export default defineConfig({
  plugins: [react()],
  server: { port: 4400 },
  build: { sourcemap: true },
});
