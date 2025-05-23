import { buildModule } from '@nomicfoundation/hardhat-ignition/modules';

export default buildModule('GianoAccountFactory', (m) => {
  const gianoAccountImplementation = m.contract('GianoSmartWallet');
  const gianoAccountFactory = m.contract('GianoSmartWalletFactory', [gianoAccountImplementation]);

  return { gianoAccountFactory };
});
