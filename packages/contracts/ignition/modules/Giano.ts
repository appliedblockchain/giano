import { buildModule } from '@nomicfoundation/hardhat-ignition/modules';
import { ethers } from 'hardhat';

export default buildModule('Giano', (m) => {
  const accountFactory = m.contract('AccountFactory');
  const erc721 = m.contract('GenericERC721');
  const erc20 = m.contract('GenericERC20', [ethers.parseEther('1000000000000000')]);

  return { accountFactory, erc721, erc20 };
});
