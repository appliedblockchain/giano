import { buildModule } from '@nomicfoundation/hardhat-ignition/modules';
import { parseEther } from 'ethers';

export default buildModule('Testing', (m) => {
  const privateERC20 = m.contract('PrivateERC20', [parseEther('100000000000000')]);
  const permissivePaymaster = m.contract('PermissivePaymaster', ['0x0000000071727De22E5E9d8BAf0edAc6f37da032']);

  m.send('fundPaymaster', permissivePaymaster, parseEther('500'));

  return { privateERC20, permissivePaymaster };
});
