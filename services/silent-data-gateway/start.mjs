// The image's entry point. It checks the environment, handles the stop signals, then loads the
// published gateway with no change to its code.
//
// CUSTOM_RPC_PROXY_URL is required. Without it the gateway falls back to http://localhost:8545,
// which in this image is the gateway's own port: every request would wait on itself and hang.
//
// The gateway sets no signal handler, and Node as PID 1 has no default action for SIGTERM, so
// `docker compose down` would wait out the stop timeout. The image runs with no init process
// (ABIP-2 hardened runtime), so this file exits on SIGTERM and SIGINT itself.

if (!process.env.CUSTOM_RPC_PROXY_URL) {
	console.error(
		"FATAL: CUSTOM_RPC_PROXY_URL is required — the node this gateway forwards to, e.g. http://anvil-sd:8545",
	);
	process.exit(1);
}

for (const signal of ["SIGTERM", "SIGINT"]) {
	process.once(signal, () => process.exit(0));
}

await import("@appliedblockchain/silentdatarollup-custom-rpc");
