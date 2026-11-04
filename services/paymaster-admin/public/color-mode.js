// Applies the colour mode before the first paint, so a dark-mode operator never sees a white flash
// while the bundle loads. A file rather than an inline <script>: the console's CSP is
// `script-src 'self'`. Kept in step with src/lib/color-mode.ts, which owns the same storage key.
(() => {
	let mode;
	try {
		mode = localStorage.getItem("giano:paymaster-admin:color-mode");
	} catch {
		// Storage can be unavailable; fall through to the browser's preference.
	}
	if (mode !== "light" && mode !== "dark")
		mode = matchMedia("(prefers-color-scheme: dark)").matches
			? "dark"
			: "light";
	document.documentElement.classList.add(mode);
	document.documentElement.style.colorScheme = mode;
})();
