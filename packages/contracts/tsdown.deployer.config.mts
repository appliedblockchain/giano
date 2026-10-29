import { defineConfig } from "tsdown";

// The giano-contracts-deployer image's CLI (Dockerfile.deployer): deploy/cli.ts and every dependency
// it imports, viem and zod included, bundled into one ESM file. The image's final stage then holds
// node, this file and the data it reads (releases/, vendor/createx/), with no node_modules, no tsx and
// no TypeScript (ABIP-2). It sits one directory below the package root, as deploy/ does, so the
// `import.meta.dirname`-relative paths in deploy/ resolve to the same files.
export default defineConfig({
	entry: { cli: "deploy/cli.ts" },
	outDir: "dist-deployer",
	format: ["esm"],
	platform: "node",
	target: "node22",
	clean: true,
	dts: false,
	outExtensions: () => ({ js: ".mjs" }),
	deps: { alwaysBundle: [/.*/], onlyBundle: false },
	tsconfig: "./tsconfig.build.json",
});
