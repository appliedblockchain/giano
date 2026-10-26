import { defineConfig } from "@wagmi/cli";
import { foundry } from "@wagmi/cli/plugins";

// ABIs for generated.ts, from a build of src/ alone (`pnpm gen:abis` runs it into out-abi/), so
// test, script and forge-std artifacts can never reach the published package.
export default defineConfig({
	out: "generated.ts",
	contracts: [],
	plugins: [
		foundry({
			project: ".",
			artifacts: "out-abi",
			forge: { build: false },
			// OpenZeppelin's UUPSUpgradeable (the paymaster's) collides by name with solady's (the
			// wallet's); forge nests the second one, and generated.ts has always exported solady's.
			exclude: ["utils/UUPSUpgradeable.sol/**"],
		}),
	],
});
