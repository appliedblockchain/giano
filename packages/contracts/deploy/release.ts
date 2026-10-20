/**
 * Contract releases: what the deploy CLI deploys. A release is cut once (`pnpm release:cut <v>`)
 * from a Foundry build and committed under releases/<version>/:
 *
 *   release.json          creation code of every deployable contract, plus the compiler identity
 *   standard-input.json   the exact solc standard-JSON input (sources, settings, remappings)
 *
 * The CLI deploys the creation code from release.json, never a fresh build, so a chain adopted
 * years from now gets byte-for-byte what every other chain on that release has. The input makes
 * the release independent of Foundry: `pnpm release:verify` recompiles it with plain solc and
 * checks it reproduces release.json.
 *
 * Releases are immutable. A contract change is a new release; see the "Releases" section of
 * packages/contracts/README.md.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Hex } from 'viem';

export const RELEASES_DIR = path.resolve(import.meta.dirname, '..', 'releases');

/** Every contract a release carries, with the source unit solc compiles it from. */
export const RELEASE_CONTRACTS = {
  GianoSmartWallet: 'src/GianoSmartWallet.sol',
  GianoSmartWalletFactory: 'src/GianoSmartWalletFactory.sol',
  GianoPaymaster: 'src/paymaster/GianoPaymaster.sol',
  ERC1967Proxy: 'node_modules/@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol',
  PrivateERC20: 'src/testing/PrivateERC20.sol',
  PermissivePaymaster: 'src/testing/PermissivePaymaster.sol',
} as const;

export type ReleaseContract = keyof typeof RELEASE_CONTRACTS;

export type Release = {
  version: string;
  compiler: { solc: string; settings: Record<string, unknown> };
  contracts: Record<ReleaseContract, { source: string; creationCode: Hex }>;
};

const VERSION = /^v\d+$/;

export function listReleases(): string[] {
  if (!fs.existsSync(RELEASES_DIR)) return [];
  return fs
    .readdirSync(RELEASES_DIR)
    .filter((entry) => VERSION.test(entry))
    .sort((a, b) => Number(a.slice(1)) - Number(b.slice(1)));
}

export function latestRelease(): string {
  const all = listReleases();
  if (all.length === 0) throw new Error(`no release under ${RELEASES_DIR}; cut one with \`pnpm release:cut v1\``);
  return all[all.length - 1];
}

export function loadRelease(version: string): Release {
  if (!VERSION.test(version)) throw new Error(`release versions look like v1, v2, …; got "${version}"`);
  const file = path.join(RELEASES_DIR, version, 'release.json');
  if (!fs.existsSync(file)) throw new Error(`release ${version} not found (${file}); known: ${listReleases().join(', ') || 'none'}`);
  return JSON.parse(fs.readFileSync(file, 'utf8')) as Release;
}
