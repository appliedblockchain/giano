#!/usr/bin/env node
// Post-build bundle scan (design.md D2, demo-deployment spec "Bundle scan").
//
// Fails the build when the public browser artifact carries something it must not:
//   * `navigator.credentials` — WebAuthn code. The thin SDK keeps every ceremony on the wallet
//     origin; its presence here means a workspace internal leaked into the demo.
//   * a `VITE_` value — build-time configuration baked into a build-once image (R16). The demo
//     reads `GIANO_*` at runtime from /config.js; the only tolerated dev fallbacks are listed below.
//   * a `.css` asset — hand-written CSS (R4). Emotion injects Chakra's styles at runtime, so a
//     stylesheet in dist/ can only come from a stylesheet import.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const dist = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'dist');
if (!fs.existsSync(dist)) {
  console.error(`scan-bundle: ${dist} does not exist — run vite build first`);
  process.exit(2);
}

/** Vite rewrites `import.meta.env.X` to a literal, so a surviving `VITE_` token is a real leak. */
const TOLERATED_VITE = new Set([]);
/**
 * RainbowKit ships its own stylesheet (and per-locale chunks of it); it is the library's CSS, not ours
 * (eslint.config.js allows exactly that import). Recognised by content — vanilla-extract's `iekbcc`
 * identifier prefix — not by file name, so a hand-written stylesheet can never hide behind a name.
 */
const isLibraryCss = (text) => /\.iekbcc\d/.test(text) || /rainbowkit/i.test(text);

const failures = [];
const walk = (dir) => {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full);
      continue;
    }
    const rel = path.relative(dist, full);
    if (entry.name.endsWith('.css')) {
      if (!isLibraryCss(fs.readFileSync(full, 'utf8'))) failures.push(`${rel}: a stylesheet was emitted — the demo writes no CSS (R4)`);
      else console.warn(`scan-bundle: ${rel} — RainbowKit stylesheet, tolerated`);
      continue;
    }
    if (!/\.(js|mjs|html)$/.test(entry.name)) continue;
    const text = fs.readFileSync(full, 'utf8');
    if (text.includes('navigator.credentials')) failures.push(`${rel}: contains navigator.credentials — WebAuthn code leaked into the dApp bundle`);
    for (const match of text.matchAll(/VITE_[A-Z0-9_]+/g)) {
      if (!TOLERATED_VITE.has(match[0])) failures.push(`${rel}: contains ${match[0]} — build-time configuration in a build-once image (R16)`);
    }
  }
};
walk(dist);

if (failures.length) {
  console.error('scan-bundle: FAILED');
  for (const failure of failures) console.error(`  - ${failure}`);
  process.exit(1);
}
console.log('scan-bundle: ok — no navigator.credentials, no VITE_ values, no hand-written CSS in dist/');
