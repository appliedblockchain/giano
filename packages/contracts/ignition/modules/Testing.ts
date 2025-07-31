import { buildModule } from '@nomicfoundation/hardhat-ignition/modules';
import { parseEther } from 'ethers';

export default buildModule('Testing', (m) => {
  const privateERC20 = m.contract('PrivateERC20', [parseEther('100000000000000')]);
  const permissivePaymasterv07 = m.contract('src/testing/PermissivePaymaster.sol:PermissivePaymaster', ['0x0000000071727De22E5E9d8BAf0edAc6f37da032'], { id: 'PermissivePaymasterV07' });
  const permissivePaymasterv08 = m.contract('PermissivePaymasterV08', ['0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108'], { id: 'PermissivePaymasterV08' });

  m.send('fundPaymasterV07', permissivePaymasterv07, parseEther('500'));
  m.send('fundPaymasterV08', permissivePaymasterv08, parseEther('500'));

  return { privateERC20, permissivePaymasterv07, permissivePaymasterv08 };
});
