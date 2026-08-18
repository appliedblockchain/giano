import { buildModule } from '@nomicfoundation/hardhat-ignition/modules';
import { parseEther } from 'ethers';

export default buildModule('Testing', (m) => {
  // A trivial faucet ERC-20 (anyone may mint/burn) — see src/testing/TestERC20.sol. No constructor
  // args and no initial supply: the demo and e2e stacks mint what they need.
  const testErc20 = m.contract('TestERC20', []);
  const permissivePaymaster = m.contract('PermissivePaymaster', ['0x0000000071727De22E5E9d8BAf0edAc6f37da032']);

  // Initial EntryPoint deposit for the paymaster (forwarded via its receive()).
  // Defaults to 500 for local anvil (free ETH); override with PAYMASTER_FUND_ETH on real
  // testnets where 500 ETH is not available, e.g. PAYMASTER_FUND_ETH=0.05.
  m.send('fundPaymaster', permissivePaymaster, parseEther(process.env.PAYMASTER_FUND_ETH ?? '500'));

  return { testErc20, permissivePaymaster };
});
