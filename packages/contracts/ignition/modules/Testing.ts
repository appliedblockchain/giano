import { buildModule } from '@nomicfoundation/hardhat-ignition/modules';
import { parseEther } from 'ethers';

export default buildModule('Testing', (m) => {
  const privateERC20 = m.contract('PrivateERC20', [parseEther('100000000000000')]);
  const permissivePaymaster = m.contract('PermissivePaymaster', ['0x0000000071727De22E5E9d8BAf0edAc6f37da032']);

  // Initial EntryPoint deposit for the paymaster (forwarded via its receive()).
  // Defaults to 500 for local anvil (free ETH); override with PAYMASTER_FUND_ETH on real
  // testnets where 500 ETH is not available, e.g. PAYMASTER_FUND_ETH=0.05.
  m.send('fundPaymaster', permissivePaymaster, parseEther(process.env.PAYMASTER_FUND_ETH ?? '500'));

  return { privateERC20, permissivePaymaster };
});
