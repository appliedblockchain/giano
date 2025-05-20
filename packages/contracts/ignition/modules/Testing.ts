import { buildModule } from '@nomicfoundation/hardhat-ignition/modules';
import { parseEther } from 'ethers';

export default buildModule('Testing', (m) => {
  const privateERC20 = m.contract('PrivateERC20', [parseEther('100000000000000')]);

  return { privateERC20 };
});
