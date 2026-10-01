#!/usr/bin/env node
// Record what hardhat-foundry would resolve, while forge is available — the giano-contracts-deployer
// build stage runs this after `hh:compile`, and hardhat.deploy.config.ts replays it in the hardened
// runtime, which has no forge and no shell to run it with.
//
// The remappings are parsed by hardhat-foundry's OWN parser from `forge remappings` output, so the
// replay cannot differ from what the plugin computed for the compile. `forge config` is recorded too,
// for the two values the plugin reads from it (src, cache_path) — a mismatch fails here, at build.
'use strict';

const { execFileSync } = require('child_process');
const { writeFileSync } = require('fs');
const path = require('path');
const { parseRemappings } = require('@nomicfoundation/hardhat-foundry/dist/src/foundry');

const root = path.resolve(__dirname, '..');
const forge = (...args) => execFileSync('forge', args, { cwd: root, encoding: 'utf8' });

const remappings = parseRemappings(forge('remappings'));
const { src, cache_path: cachePath } = JSON.parse(forge('config', '--json'));
if (path.resolve(root, src) !== path.resolve(root, 'src')) {
  throw new Error(`forge src is ${src}; hardhat.base.ts sources is ./src — the deploy config would compile different sources`);
}
if (path.resolve(root, cachePath) === path.resolve(root, 'cache')) {
  throw new Error(`forge cache_path is ${cachePath}, which hardhat-foundry would move hardhat's cache away from`);
}

const out = path.join(root, 'foundry.snapshot.json');
writeFileSync(out, `${JSON.stringify({ remappings, src, cache_path: cachePath }, null, 2)}\n`);
console.log(`wrote ${out}: ${Object.keys(remappings).length} remappings`);
