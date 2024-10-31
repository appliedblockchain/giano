import { defineConfig } from 'tsup';

export default defineConfig({
  format: ['esm', 'cjs'],
  noExternal: ['@appliedblockchain/giano-common'],
  sourcemap: true,
  clean: true,
});
