import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // dev parity with the nginx proxy: /api and /.well-known go to the wallet-api
    proxy: {
      '/api': { target: 'http://localhost:8080', changeOrigin: true, rewrite: (p) => p.replace(/^\/api/, '') },
      '/.well-known/webauthn': { target: 'http://localhost:8080', changeOrigin: true },
    },
  },
  build: { sourcemap: true },
});
