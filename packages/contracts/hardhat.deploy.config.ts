// Deploy-only Hardhat config, used by the giano-contracts-deployer image (scripts/deployer-entrypoint.mjs).
//
// That image runs on a Docker Hardened Image runtime (ABIP-2): no shell, no forge. hardhat-foundry
// shells out to `forge config` and `forge remappings` the moment a config that imports it loads, so
// this config does not import it. It replays the remappings the build stage recorded instead
// (scripts/snapshot-foundry.cjs → foundry.snapshot.json), parsed by hardhat-foundry's own parser
// while forge was still there. Same settings (hardhat.base.ts), same remappings, same sources: the
// compile the deployment runs finds the build stage's artefacts current, and the bytecode — hence
// every CREATE2 address — is the build stage's.
import { readFileSync } from 'fs';
import { join } from 'path';
import { TASK_COMPILE_GET_REMAPPINGS } from 'hardhat/builtin-tasks/task-names';
import type { HardhatUserConfig } from 'hardhat/config';
import { subtask } from 'hardhat/config';
import '@nomicfoundation/hardhat-toolbox';
import '@nomicfoundation/hardhat-ignition-ethers';
import { baseConfig } from './hardhat.base';

const SNAPSHOT = join(__dirname, 'foundry.snapshot.json');

subtask(TASK_COMPILE_GET_REMAPPINGS).setAction(async (): Promise<Record<string, string>> => {
  let snapshot: { remappings?: Record<string, string> };
  try {
    snapshot = JSON.parse(readFileSync(SNAPSHOT, 'utf8'));
  } catch (err) {
    throw new Error(`${SNAPSHOT} is missing or unreadable — it is written by scripts/snapshot-foundry.cjs in the image build stage (${err})`);
  }
  if (!snapshot.remappings) throw new Error(`${SNAPSHOT} has no "remappings"`);
  return snapshot.remappings;
});

const config: HardhatUserConfig = baseConfig;

export default config;
