import { buildModule } from '@nomicfoundation/hardhat-ignition/modules';
import hre, { ethers } from 'hardhat';
import P256Precompile from './P256Precompile';

export default buildModule('Giano', (m) => {
  // bytecode of contract available at https://github.com/daimo-eth/p256-verifier/tree/master

  void ethers.provider.getNetwork().then((n) => {
    // if this is Hardhat, deploy precompile code at the expected predetermined address
    if (n.chainId === 31337n) {
      void hre.network.provider.send('hardhat_setCode', ['0xc2b78104907F722DABAc4C69f826a522B2754De4', P256Precompile]);
    }
  });
  const accountFactory = m.contract('AccountFactory');
  const accountRegistry = m.contract('AccountRegistry', [accountFactory]);

  return { accountRegistry, accountFactory };
});
