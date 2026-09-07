/**
 * Runs a command against an anvil from the **pinned** foundry image, then tears it down.
 *
 * Exists because the anvil that writes `state.json` must be the anvil that loads it: `--load-state`
 * parsing is version-specific, and a state dumped by a developer's local anvil can be unloadable by
 * the image the deployment runs. Rather than asking people to remember that, this makes the pinned
 * version the default path.
 *
 * Usage:  node e2e/devnet/with-pinned-anvil.mjs <command> [args...]
 */
import { execFileSync, spawn } from 'node:child_process';

/** Keep in step with deploy/docker-compose.e2e.yml and services/devnet/Dockerfile. */
const IMAGE = 'ghcr.io/foundry-rs/foundry@sha256:8347b728d5d393dac1c018691b36f506d23b9dcd78341d40ea0fcb11c3a19cdd';
const NAME = 'giano-devnet-generator';
const PORT = Number(process.env.ANVIL_PORT ?? 8545);

const [command, ...args] = process.argv.slice(2);
if (!command) throw new Error('usage: with-pinned-anvil.mjs <command> [args...]');

function docker(argv, options = {}) {
  return execFileSync('docker', argv, { encoding: 'utf8', ...options });
}

// A leftover container from an interrupted run would silently serve the wrong chain.
try {
  docker(['rm', '-f', NAME], { stdio: 'ignore' });
} catch {
  // nothing to remove
}

console.log(`Starting pinned anvil (${IMAGE.slice(0, 40)}…) on :${PORT}`);
docker([
  'run', '-d', '--name', NAME, '-p', `${PORT}:8545`,
  '--entrypoint', 'anvil', IMAGE,
  '--host', '0.0.0.0', '--chain-id', '31337', '--silent',
]);

let failed = false;
try {
  for (let i = 0; ; i++) {
    try {
      const response = await fetch(`http://127.0.0.1:${PORT}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'web3_clientVersion', params: [] }),
      });
      const body = await response.json();
      console.log(`  ${body.result}`);
      break;
    } catch (error) {
      if (i > 120) throw error;
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }

  const child = spawn(command, args, {
    stdio: 'inherit',
    env: { ...process.env, RPC_URL: `http://127.0.0.1:${PORT}` },
  });
  const code = await new Promise((resolve) => child.on('exit', resolve));
  if (code !== 0) failed = true;
} finally {
  // Always tear down: a stray container holding :8545 shadows every later stack.
  try {
    docker(['rm', '-f', NAME], { stdio: 'ignore' });
  } catch {
    // already gone
  }
}

process.exit(failed ? 1 : 0);
