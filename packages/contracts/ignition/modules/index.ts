import { buildModule } from '@nomicfoundation/hardhat-ignition/modules';
import GianoAccountFactoryModule from './GianoAccountFactory';

export default buildModule('All', (m) => {
  const gianoAccountFactory = m.useModule(GianoAccountFactoryModule);

  return { ...gianoAccountFactory };
});
