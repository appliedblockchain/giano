import { defineConfig } from '@playwright/test';

/**
 * Two real origins via localtest.me-style hosts:
 *  - dApp:   http://app.localtest.me:4400 (static fixture using ONLY the thin SDK)
 *  - wallet: http://wallet.localtest.me:8081 (wallet-web container / vite preview)
 * The stack comes from deploy/docker-compose.e2e.yml (anvil devnet + alto + wallet-api
 * + wallet-web). WebAuthn uses the CDP virtual authenticator on the popup page —
 * Chromium-only; Safari/Firefox get a transport-only smoke via GIANO_E2E_FAKE_WEBAUTHN.
 */
export default defineConfig({
  testDir: './tests',
  timeout: 120_000,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1, // wallet sessions/popups are stateful — serialize
  use: {
    baseURL: process.env.DAPP_URL ?? 'http://app.localtest.me:4400',
    trace: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: {
        browserName: 'chromium',
        launchOptions: {
          args: [
            // localtest.me over http is not a secure context; WebAuthn requires one
            '--unsafely-treat-insecure-origin-as-secure=http://wallet.localtest.me:8081,http://app.localtest.me:4400',
          ],
        },
      },
    },
  ],
  webServer: {
    command: 'node dapp/serve.mjs',
    url: 'http://app.localtest.me:4400',
    reuseExistingServer: true,
  },
});
