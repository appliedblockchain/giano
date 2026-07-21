import * as dotenv from 'dotenv';
import { TASK_COMPILE } from 'hardhat/builtin-tasks/task-names';
import type { HardhatUserConfig } from 'hardhat/config';
import { task } from 'hardhat/config';
import '@nomicfoundation/hardhat-toolbox';
import '@nomicfoundation/hardhat-ignition-ethers';
import 'hardhat-gas-reporter';
import 'hardhat-tracer';
import '@nomicfoundation/hardhat-foundry';
dotenv.config();

task(TASK_COMPILE).setAction(async (taskArgs, hre, runSuper) => {
  await runSuper(taskArgs);
});

/** @type import('hardhat/config').HardhatUserConfig */
const config: HardhatUserConfig = {
  solidity: {
    compilers: [
      {
        version: '0.8.28',
        settings: {
          optimizer: {
            enabled: true,
            runs: 200,
          },
          viaIR: true,
        },
      },
    ],
  },
  networks: {
    hardhat: {
      enableRip7212: true,
    },
    localhost: {
      enableRip7212: true,
      url: 'http://localhost:8545',
    },
    ['base-sepolia']: {
      enableRip7212: true,
      url: process.env.BASE_SEPOLIA_RPC_URL ?? 'https://base-sepolia.public.blastapi.io',
      accounts: process.env.BASE_PRIVATE_KEY ? [process.env.BASE_PRIVATE_KEY] : [],
      chainId: 84532,
    },
    base: {
      enableRip7212: true,
      url: process.env.BASE_RPC_URL ?? 'https://base-rpc.publicnode.com',
      accounts: process.env.BASE_PRIVATE_KEY ? [process.env.BASE_PRIVATE_KEY] : [],
      chainId: 8453,
    },
  },
  gasReporter: {
    enabled: true,
  },
  paths: {
    sources: './src',
  },
  ignition: {
    strategyConfig: {
      create2: {
        salt: '0xAB000000000000000000000000000000000000000000000000000000000000AB',
      },
    },
  },
};

export default config;
