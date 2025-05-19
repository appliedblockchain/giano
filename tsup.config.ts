import { defineConfig } from 'tsup';

export default defineConfig({
  format: ['esm', 'cjs'],
  dts: true,
  noExternal: ['@appliedblockchain/giano-common'],
  sourcemap: true,
  clean: true,
  tsconfig: './tsconfig.json',
});
