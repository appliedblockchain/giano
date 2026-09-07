import { defineConfig } from '@playwright/test';

import { ORIGINS, loopbackOf, portOf } from './origins.mjs';

/**
 * Two-tenant, four-origin topology against ONE shared backend stack
 * (deploy/docker-compose.e2e.yml):
 *  - tenant "stock": dApp http://app.localhost     → wallet http://wallet.localhost
 *                    (Giano's stock wallet-web container)
 *  - tenant "byo":   dApp http://app-byo.localhost → wallet http://wallet-byo.localhost
 *                    (tenant-built vanilla-TS fixture, e2e/wallet-byo/)
 * Those names are served by portless on port 80 (see origins.mjs and portless-setup.mjs),
 * which is why no origin here carries a port.
 * WebAuthn uses the CDP virtual authenticator on the popup page — Chromium-only.
 */
export default defineConfig({
  testDir: './tests',
  timeout: 120_000,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1, // one shared backend + stateful wallet popups — serialize
  // Registers the demo's names with portless and refuses to start until they answer.
  globalSetup: './portless-setup.mjs',
  use: {
    baseURL: process.env.DAPP_URL ?? ORIGINS.dapp,
    trace: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { browserName: 'chromium' },
    },
  ],
  // The fixtures listen on fixed loopback ports and portless publishes each one under a
  // name; `url` below is deliberately the loopback address rather than the name, so that
  // this readiness check tests the fixture alone and stays independent of both the proxy
  // and the order Playwright runs `webServer` and `globalSetup` in. portless-setup.mjs is
  // what proves the names themselves resolve.
  webServer: [
    {
      // tenant A dApp
      command: 'node dapp/serve.mjs',
      env: { DAPP_PORT: String(portOf('app')), WALLET_URL: process.env.WALLET_URL ?? ORIGINS.wallet },
      url: loopbackOf('app'),
      reuseExistingServer: true,
    },
    {
      // tenant B dApp (same fixture, different wallet origin)
      command: 'node dapp/serve.mjs',
      env: { DAPP_PORT: String(portOf('app-byo')), WALLET_URL: process.env.WALLET_BYO_URL ?? ORIGINS.walletByo },
      url: loopbackOf('app-byo'),
      reuseExistingServer: true,
    },
    {
      // tenant B wallet origin (BYO UI + /api proxy to the wallet-api container)
      command: 'node wallet-byo/serve.mjs',
      env: { BYO_WALLET_PORT: String(portOf('wallet-byo')), WALLET_API_UPSTREAM: process.env.WALLET_API_UPSTREAM ?? loopbackOf('api') },
      url: loopbackOf('wallet-byo'),
      reuseExistingServer: true,
    },
  ],
});
