import { buildModule } from '@nomicfoundation/hardhat-ignition/modules';

export default buildModule('Giano', (m) => {

  const accountFactory = m.contract('AccountFactory');
  const accountRegistry = m.contract('AccountRegistry', [accountFactory]);

  return { accountRegistry, accountFactory };
});
