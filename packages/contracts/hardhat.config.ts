import { SignatureType } from '@appliedblockchain/silentdatarollup-core';
import * as dotenv from 'dotenv';
import type { HardhatUserConfig } from 'hardhat/config';
import '@nomicfoundation/hardhat-toolbox';
import '@nomicfoundation/hardhat-ignition-ethers';
import 'hardhat-gas-reporter';
import 'hardhat-tracer';
import '@appliedblockchain/silentdatarollup-hardhat-plugin';
dotenv.config();

/** @type import('hardhat/config').HardhatUserConfig */
const config: HardhatUserConfig = {
  solidity: {
    compilers: [
      {
        version: '0.8.27',
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
    sdr: {
      url: process.env.SDR_URL,
      accounts: [process.env.SDR_PRIVATE_KEY!],
      silentdata: {
        authSignatureType: SignatureType.Raw,
      },
    },
  },
  gasReporter: {
    enabled: true,
  },
  ignition: {
    strategyConfig: {
      create2: {
        salt: '0x0000000000000000000000000000000000000000000000000000000000000000',
      },
    },
  },
};

export default config;
