// Everything both Hardhat configs share: compiler settings, networks, paths, the Ignition CREATE2
// salt. Split out so the deploy config (hardhat.deploy.config.ts) cannot drift from the one that
// compiles — every value here feeds the bytecode or the deployment, hence the CREATE2 addresses.
//
// Plugins are NOT imported here: hardhat.config.ts adds the full development set, including
// hardhat-foundry; the deploy config adds only what a deployment needs.
import * as dotenv from 'dotenv';
import type { HardhatUserConfig } from 'hardhat/config';
dotenv.config();

export const baseConfig: HardhatUserConfig = {
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
    // Ethereum Sepolia testnet. Used by the Sepolia e2e demo (deploy/docker-compose.sepolia.yml).
    // Sepolia provides the RIP-7212 precompile at 0x100 (verify with `pnpm run doctor chain`), so
    // P256 signatures are verified by the precompile; webauthn-sol falls back to the in-contract
    // FreshCryptoLib path only on chains without it.
    sepolia: {
      url: process.env.DEPLOY_RPC_URL ?? process.env.SEPOLIA_RPC_URL ?? 'https://ethereum-sepolia-rpc.publicnode.com',
      accounts: process.env.DEPLOYER_PRIVATE_KEY ? [process.env.DEPLOYER_PRIVATE_KEY] : [],
      chainId: 11155111,
    },
    // Generic env-driven target — deploy to ANY EVM chain with `--network custom`:
    //   DEPLOY_RPC_URL=... DEPLOY_CHAIN_ID=... DEPLOYER_PRIVATE_KEY=0x... pnpm hh:deploy --network custom
    custom: {
      url: process.env.DEPLOY_RPC_URL ?? 'http://localhost:8545',
      accounts: process.env.DEPLOYER_PRIVATE_KEY ? [process.env.DEPLOYER_PRIVATE_KEY] : [],
      chainId: process.env.DEPLOY_CHAIN_ID ? Number(process.env.DEPLOY_CHAIN_ID) : undefined,
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

