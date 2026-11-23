import { readFileSync } from "node:fs";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The installed connector's version, shown in the header and compared with wallet-api in the preflight.
// Read from the installed package manifest at build time: the connector's exports map does not expose
// it, and importing anything else from the package would breach the published-surface rule (R2).
const connectorVersion: string = (
	JSON.parse(
		readFileSync(
			new URL(
				"./node_modules/@appliedblockchain/giano-connector/package.json",
				import.meta.url,
			),
			"utf8",
		),
	) as { version: string }
).version;

// The demo is reached at http://demo.localhost (tenant stock) and http://demo-byo.localhost (tenant byo),
// names portless serves for the loopback ports below (e2e/origins.mjs). They are distinct from the e2e
// fixture's app/app-byo names on purpose: the two used to share 4400/4401 and Playwright's
// `reuseExistingServer` would silently adopt this app instead of the fixture. No COOP header is set, so
// the wallet popup keeps `window.opener` (required by the transport).
export default defineConfig({
	plugins: [react()],
	// The same GIANO_* names as the container, from .env.development / .env.local, for `pnpm dev` only (see src/config.ts).
	envPrefix: "GIANO_",
	// `dev:stock` and `dev:byo` run side by side from this directory: the demo E2E leg starts both.
	// With one shared cache, one server's dependency optimization replaces the other's files during
	// the session. The browser then loads two copies of a shared chunk, wagmi and RainbowKit get
	// different React contexts, and the adapters card throws WagmiProviderNotFoundError.
	// The name has no GIANO_ prefix on purpose, so it never reaches the browser bundle.
	cacheDir: process.env.DEMO_VITE_CACHE_DIR ?? "node_modules/.vite",
	define: { __GIANO_CONNECTOR_VERSION__: JSON.stringify(connectorVersion) },
	server: { port: 4410 },
	build: { sourcemap: true },
});
