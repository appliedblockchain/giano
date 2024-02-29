import { network } from 'hardhat';
import type { HardhatUserConfig } from 'hardhat/config';
import { extendEnvironment } from 'hardhat/config';
import '@nomicfoundation/hardhat-toolbox';
import 'hardhat-gas-reporter';

/** @type import('hardhat/config').HardhatUserConfig */
const config: HardhatUserConfig = {
  solidity: {
    compilers: [
      {
        version: '0.8.19',
        settings: {
          optimizer: {
            enabled: true,
            runs: 200,
          },
        },
      },
    ],
  },
  networks: {
    hardhat: {
      mining: {
        auto: false,
        interval: 10000,
      },
    },
    localhost: {
      url: 'http://localhost:8545',
      accounts: ['0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'],
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
