import type { HardhatUserConfig } from 'hardhat/config';
import '@nomicfoundation/hardhat-toolbox';
import '@nomicfoundation/hardhat-ignition-ethers';
import 'hardhat-gas-reporter';
import 'hardhat-tracer';

/** @type import('hardhat/config').HardhatUserConfig */
const config: HardhatUserConfig = {
  solidity: {
    compilers: [
      {
        version: '0.8.23',
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
  },
  gasReporter: {
    enabled: true,
  },
};

export default config;
