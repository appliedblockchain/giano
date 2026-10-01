// Write this chain's registry entry, in the shared schema, to $OUT_DIR/giano-addresses.<chainId>.json.
// The last step of the giano-contracts-deployer image (scripts/deployer-entrypoint.mjs), run after
// `gen:addresses` has regenerated addresses.ts from the Ignition journal.
import * as fs from 'fs';
import { gianoAddresses } from '../addresses';

const chainId = Number(process.env.CHAIN_ID);
const deployment = gianoAddresses[chainId];
if (!deployment) throw new Error(`no registry entry generated for chain ${chainId}`);
const path = `${process.env.OUT_DIR}/giano-addresses.${chainId}.json`;
fs.writeFileSync(path, JSON.stringify({ chainId, ...deployment }, null, 2));
console.log(`wrote ${path}`);
