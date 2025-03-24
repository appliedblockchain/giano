import { buildModule } from '@nomicfoundation/hardhat-ignition/modules';
import GianoModule from './Giano';
import TestingModule from './Testing';

export default buildModule('All', (m) => {
  const giano = m.useModule(GianoModule);
  const testing = m.useModule(TestingModule);

  return { ...giano, ...testing };
});
