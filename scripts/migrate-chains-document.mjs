#!/usr/bin/env node
// Rewrites a flat backend chain document — the `chains` secret as wallet-api and paymaster-admin read
// it before per-service sections (packages/contracts/chains.ts) — into the sectioned shape. One-shot,
// for re-authoring the secret; reads stdin, writes stdout, explains to stderr:
//
//   pbpaste | node scripts/migrate-chains-document.mjs | pbcopy
//
// `bundlerUrl` is dropped: wallet-api now derives it from BUNDLER_BASE_URL. A chain that really is
// submitted through another bundler needs `walletApi.bundlerUrl` and `bundler.enabled: false` put
// back by hand — the script lists every URL it drops, so nothing disappears silently. A field it does
// not recognise stops it rather than being guessed at.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const SHARED = ['chainId', 'name', 'rpcUrl', 'nativeCurrency', 'entryPoint', 'sponsorshipPaymaster'];
const SECTIONS = { walletApi: ['factory', 'policy'], paymasterAdmin: ['walletRpcUrl', 'refreshSeconds'] };
const DROPPED = ['bundlerUrl'];

/** @returns {{ document: object[], notes: string[] }} */
export function migrate(input) {
  if (!Array.isArray(input)) throw new Error('the chain document must be a JSON array');
  const notes = [];
  const document = input.map((entry, index) => {
    const label = `entry ${index} (chain ${entry?.chainId ?? '?'})`;
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) throw new Error(`${label} is not an object`);
    if (Object.keys(SECTIONS).some((section) => section in entry) || 'bundler' in entry) {
      throw new Error(`${label} already has per-service sections — nothing to migrate`);
    }
    const out = {};
    const sections = {};
    for (const [key, value] of Object.entries(entry)) {
      if (SHARED.includes(key)) {
        out[key] = value;
      } else if (DROPPED.includes(key)) {
        notes.push(`${label}: dropped ${key} ${JSON.stringify(value)} — wallet-api derives it from BUNDLER_BASE_URL now`);
      } else {
        const section = Object.keys(SECTIONS).find((name) => SECTIONS[name].includes(key));
        if (!section) throw new Error(`${label}: unrecognised field "${key}" — move it by hand`);
        (sections[section] ??= {})[key] = value;
      }
    }
    return { ...out, ...sections };
  });
  return { document, notes };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const { document, notes } = migrate(JSON.parse(readFileSync(0, 'utf8')));
    for (const note of notes) console.error(note);
    process.stdout.write(`${JSON.stringify(document, null, 2)}\n`);
  } catch (error) {
    console.error(`FATAL: ${error.message}`);
    process.exit(1);
  }
}
