import { defineConfig } from '@playwright/test';

/**
 * Two-tenant, four-origin topology against ONE shared backend stack
 * (deploy/docker-compose.e2e.yml):
 *  - tenant "stock": dApp http://app.localhost:4400     → wallet http://wallet.localhost:8081
 *                    (Giano's stock wallet-web container)
 *  - tenant "byo":   dApp http://app-byo.localhost:4401 → wallet http://wallet-byo.localhost:8082
 *                    (tenant-built vanilla-TS fixture, e2e/wallet-byo/)
 * WebAuthn uses the CDP virtual authenticator on the popup page — Chromium-only.
 */
export default defineConfig({
  testDir: './tests',
  timeout: 120_000,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1, // one shared backend + stateful wallet popups — serialize
  use: {
    baseURL: process.env.DAPP_URL ?? 'http://app.localhost:4400',
    trace: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { browserName: 'chromium' },
    },
  ],
  webServer: [
    {
      // tenant A dApp
      command: 'node dapp/serve.mjs',
      env: { DAPP_PORT: '4400', WALLET_URL: process.env.WALLET_URL ?? 'http://wallet.localhost:8081' },
      url: 'http://127.0.0.1:4400',
      reuseExistingServer: true,
    },
    {
      // tenant B dApp (same fixture, different wallet origin)
      command: 'node dapp/serve.mjs',
      env: { DAPP_PORT: '4401', WALLET_URL: process.env.WALLET_BYO_URL ?? 'http://wallet-byo.localhost:8082' },
      url: 'http://127.0.0.1:4401',
      reuseExistingServer: true,
    },
    {
      // tenant B wallet origin (BYO UI + /api proxy to the published wallet-api port)
      command: 'node wallet-byo/serve.mjs',
      env: { BYO_WALLET_PORT: '8082', WALLET_API_UPSTREAM: process.env.WALLET_API_UPSTREAM ?? 'http://127.0.0.1:8080' },
      url: 'http://127.0.0.1:8082',
      reuseExistingServer: true,
    },
  ],
});
