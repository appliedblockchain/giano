import { defineConfig } from 'tsup';

export default defineConfig({
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  tsconfig: './tsconfig.json',
});
