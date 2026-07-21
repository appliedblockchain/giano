import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    embedded: 'src/embedded.ts',
    'index-web': 'src/index-web.ts',
    'index-node': 'src/index-node.ts',
  },
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  tsconfig: './tsconfig.json',
});
