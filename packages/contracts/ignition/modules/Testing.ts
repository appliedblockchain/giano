import { buildModule } from '@nomicfoundation/hardhat-ignition/modules';

export default buildModule('Testing', (m) => {
  const testContract = m.contract('TestContract');

  return { testContract };
});
