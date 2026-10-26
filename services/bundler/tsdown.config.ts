import { defineConfig } from "tsdown";

export default defineConfig({
	entry: { index: "src/index.ts" },
	format: ["esm"],
	platform: "node",
	target: "node22",
	sourcemap: true,
	clean: true,
	// An application, not a library: no declarations. `.js` because the package is "type": "module".
	dts: false,
	outExtensions: () => ({ js: ".js" }),
	tsconfig: "./tsconfig.json",
});
