import { defineConfig } from "tsdown";

// Two builds rather than one: declarations are for the library, and the CLI is an executable that
// nothing imports. `cli` is a second entry rather than a separate package: it is a thin shell over
// the same client, and splitting it would mean versioning the two in step forever.
const shared = {
	format: ["esm", "cjs"],
	platform: "node",
	target: "es2022",
	sourcemap: true,
	tsconfig: "./tsconfig.json",
	// The file names package.json `exports` and `bin` name: .mjs for ESM, .js for CJS.
	outExtensions: ({ format }) => ({
		js: format === "es" ? ".mjs" : ".js",
		dts: format === "es" ? ".d.mts" : ".d.ts",
	}),
} as const satisfies Parameters<typeof defineConfig>[0];

export default defineConfig([
	{
		...shared,
		entry: { index: "src/index.ts" },
		clean: true,
		// Declarations from each source file alone (isolatedDeclarations): no TypeScript compiler involved,
		// so the build does not depend on its API. An export without explicit types fails the build.
		dts: { generator: "oxc" },
	},
	{
		...shared,
		entry: { cli: "cli/index.ts" },
		clean: false,
		dts: false,
	},
]);
