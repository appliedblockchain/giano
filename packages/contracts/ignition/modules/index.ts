import { buildModule } from '@nomicfoundation/hardhat-ignition/modules';
import GianoModule from './Giano';
import SingleKeyAccountFactoryModule from './SingleKeyAccountFactory';
import TestingModule from './Testing';

export default buildModule('All', (m) => {
  const giano = m.useModule(GianoModule);
  const singleKey = m.useModule(SingleKeyAccountFactoryModule)
  const testing = m.useModule(TestingModule);

  return { ...giano, ...testing, ...singleKey };
});
