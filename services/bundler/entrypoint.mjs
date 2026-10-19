// giano-bundler entrypoint: validate the environment, then run alto IN this process.
//
// The image is a Docker Hardened Image runtime (ABIP-2): no shell, no tini, no npm. So the checks
// entrypoint.sh used to make are made here, and alto is imported rather than exec'd — one process,
// PID 1, which is why it installs its own SIGTERM handler: Node as PID 1 has no default action for
// it, and without one ECS waits out the stop timeout and sends SIGKILL.
//
// Refuses to start with missing keys, or with the well-known Anvil key unless GIANO_DEV_MODE=true.

import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';

// The well-known Anvil account 0 key — never legitimate outside a devnet.
export const ANVIL_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
export const DEFAULT_ENTRYPOINT = '0x0000000071727De22E5E9d8BAf0edAc6f37da032';

export class ConfigError extends Error {}

/**
 * The `alto run …` arguments for an environment, plus any warning to log.
 * @param {Record<string, string | undefined>} env
 * @returns {{ args: string[], warning?: string }}
 */
export function altoArgs(env) {
  const rpcUrl = env.ALTO_RPC_URL;
  if (!rpcUrl) throw new ConfigError('ALTO_RPC_URL is required');

  const executorKeys = env.ALTO_EXECUTOR_PRIVATE_KEYS;
  if (!executorKeys) {
    throw new ConfigError('FATAL: ALTO_EXECUTOR_PRIVATE_KEYS is required (executor keys sign bundle transactions)');
  }

  let warning;
  if (`${executorKeys}${env.ALTO_UTILITY_PRIVATE_KEY ?? ''}`.includes(ANVIL_KEY)) {
    if ((env.GIANO_DEV_MODE ?? 'false') !== 'true') {
      throw new ConfigError(
        'FATAL: refusing to start with the well-known Anvil key outside dev mode (set GIANO_DEV_MODE=true for local devnets only)',
      );
    }
    warning = 'WARNING: running with the well-known Anvil key (GIANO_DEV_MODE=true) — never do this against a real chain';
  }

  const args = [
    'run',
    '--rpc-url', rpcUrl,
    '--entrypoints', env.ALTO_ENTRYPOINTS || DEFAULT_ENTRYPOINT,
    '--executor-private-keys', executorKeys,
    ...(env.ALTO_UTILITY_PRIVATE_KEY ? ['--utility-private-key', env.ALTO_UTILITY_PRIVATE_KEY] : []),
    '--safe-mode', env.ALTO_SAFE_MODE || 'true',
    '--port', env.ALTO_PORT || '4337',
  ];
  return { args, warning };
}

async function main() {
  let config;
  try {
    config = altoArgs(process.env);
  } catch (err) {
    if (!(err instanceof ConfigError)) throw err;
    console.error(err.message);
    process.exit(1);
  }
  if (config.warning) console.error(config.warning);

  for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => process.exit(0));

  // alto's `exports` map hides its package.json and CLI from the resolver, so the CLI is found where
  // the image installs it — node_modules beside this file (/app) — through the package's own `bin`.
  const pkgDir = new URL('./node_modules/@pimlico/alto/', import.meta.url);
  const { bin } = JSON.parse(readFileSync(new URL('package.json', pkgDir), 'utf8'));
  const cli = new URL(bin.alto, pkgDir);
  // alto parses process.argv (yargs hideBin) when its CLI module loads
  process.argv = [process.argv[0], fileURLToPath(cli), ...config.args];
  await import(cli.href);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
