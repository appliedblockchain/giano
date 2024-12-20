import type { HardhatUserConfig } from 'hardhat/config';
import { extendEnvironment } from 'hardhat/config';
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
      mining: {
        auto: false,
        interval: 10000,
      },
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

// when we run tests, we are enabling auto-mining to not wait for contract deployment and tx mining
extendEnvironment(async (hre) => {
  if (process.env.NODE_ENV === 'test') {
    await hre.network.provider.send('evm_setAutomine', [true]);
    await hre.network.provider.send('evm_setIntervalMining', [0]);
  }
});

export default config;
