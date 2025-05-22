import { buildModule } from '@nomicfoundation/hardhat-ignition/modules';

export default buildModule('CredentialKeyMapper', (m) => {
  const credentialKeyMapper = m.contract('CredentialKeyMapper');

  return { credentialKeyMapper };
});
