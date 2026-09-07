// Placeholder runtime config, copied into dist/ by Vite and OVERWRITTEN at container start by
// docker/entrypoint.sh (which renders docker/config.js.template over it).
//
// It exists so index.html can load /config.js unconditionally: under `pnpm dev` and
// `pnpm preview` there is no container to render one, and a 404 on a <script> tag would leave
// Vite's SPA fallback serving index.html as JavaScript. Leaving the value null makes
// src/config.ts fall back to the build-time VITE_* variables, which is exactly what local
// development wants.
window.__GIANO_CONFIG__ = null;
