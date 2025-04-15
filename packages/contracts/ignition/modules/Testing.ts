import { buildModule } from '@nomicfoundation/hardhat-ignition/modules';
import { ethers } from 'ethers';

export default buildModule('Testing', (m) => {
  const initialERC20Supply = m.getParameter('initialERC20Supply', ethers.parseEther('1000000000'))
  const testContract = m.contract('TestContract');
  const genericERC20 = m.contract('GenericERC20', [initialERC20Supply]);
  const genericERC721 = m.contract('GenericERC721');

  return { testContract, genericERC20, genericERC721 };
});
