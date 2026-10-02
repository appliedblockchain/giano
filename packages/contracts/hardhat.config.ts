import { TASK_COMPILE } from 'hardhat/builtin-tasks/task-names';
import type { HardhatUserConfig } from 'hardhat/config';
import { task } from 'hardhat/config';
import '@nomicfoundation/hardhat-toolbox';
import '@nomicfoundation/hardhat-ignition-ethers';
import 'hardhat-gas-reporter';
import 'hardhat-tracer';
import '@nomicfoundation/hardhat-foundry';
import { baseConfig } from './hardhat.base';

task(TASK_COMPILE).setAction(async (taskArgs, hre, runSuper) => {
  await runSuper(taskArgs);
});

// The development config: compile, test, deploy from a workstation. hardhat-foundry resolves the
// lib/ submodule remappings (solady) by running `forge`. The giano-contracts-deployer image cannot run
// it — no shell in a hardened runtime — and uses hardhat.deploy.config.ts with a build-time snapshot
// of the same remappings instead.
const config: HardhatUserConfig = baseConfig;

export default config;
