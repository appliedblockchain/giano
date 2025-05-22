import { buildModule } from '@nomicfoundation/hardhat-ignition/modules';
import CredentialKeyMapperModule from './CredentialKeyMapper';
import GianoAccountFactoryModule from './GianoAccountFactory';

export default buildModule('All', (m) => {
  const gianoAccountFactory = m.useModule(GianoAccountFactoryModule);
  const credentialKeyMapper = m.useModule(CredentialKeyMapperModule);

  return { ...gianoAccountFactory, ...credentialKeyMapper };
});
