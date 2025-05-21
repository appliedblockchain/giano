import { buildModule } from '@nomicfoundation/hardhat-ignition/modules';
import { parseEther } from 'ethers';

export default buildModule('Testing', (m) => {
  const privateERC20 = m.contract('PrivateERC20', [parseEther('100000000000000')]);
  const permissivePaymaster = m.contract('PermissivePaymaster', ['0x4337084d9e255ff0702461cf8895ce9e3b5ff108']);

  m.send('fundPaymaster', permissivePaymaster, parseEther('500'));

  return { privateERC20, permissivePaymaster };
});
