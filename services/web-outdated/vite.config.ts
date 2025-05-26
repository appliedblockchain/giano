import react from '@vitejs/plugin-react-swc';
import { defineConfig } from 'vite';
import tsconfigPaths from 'vite-tsconfig-paths';

export default defineConfig({
  plugins: [react({ tsDecorators: true }), tsconfigPaths()],
  envDir: './', // by default vite will look into root directory for .env
  root: 'src/client',
  build: {
    outDir: './dist',
  },
  server: {
    host: '0.0.0.0',
    port: Number(3000),
    proxy: {
      '/api': {
        target: 'http://localhost',
        changeOrigin: true,
        secure: false,
        ws: true,
      },
    },
  },
  define: {
    'window.global': {},
  },
});
