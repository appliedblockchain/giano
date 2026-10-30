import { readFileSync } from "node:fs";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
	plugins: [
		react(),
		{
			name: "wallet-runtime-config",
			configureServer(server) {
				server.middlewares.use((request, response, next) => {
					if (request.url?.split("?")[0] !== "/config.json") return next();
					const config = JSON.parse(
						readFileSync(
							new URL("./public/config.json", import.meta.url),
							"utf8",
						),
					);
					config.passkeyDevicePreference =
						process.env.GIANO_PASSKEY_DEVICE_PREFERENCE ?? "browser-default";
					response.setHeader("Content-Type", "application/json");
					response.end(JSON.stringify(config));
				});
			},
		},
	],
	server: {
		port: 5173,
		// dev parity with the nginx proxy: /api and /.well-known go to the wallet-api
		proxy: {
			"/api": {
				target: "http://localhost:8080",
				changeOrigin: true,
				rewrite: (p) => p.replace(/^\/api/, ""),
			},
			"/.well-known/webauthn": {
				target: "http://localhost:8080",
				changeOrigin: true,
			},
		},
	},
	build: { sourcemap: true },
});
