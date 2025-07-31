import { defineConfig } from '@wagmi/cli';
import { hardhat } from '@wagmi/cli/plugins';

export default defineConfig({
  out: 'generated.ts',
  contracts: [],
  plugins: [
    hardhat({
      project: '.',
      exclude: [
        // Exclude account-abstraction contracts to avoid naming conflicts
        '**/account-abstraction-v07/**',
        '**/account-abstraction-v08/**',
      ],
    }),
  ],
});
