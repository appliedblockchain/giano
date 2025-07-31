import { buildModule } from '@nomicfoundation/hardhat-ignition/modules';

export default buildModule('GianoAccountFactory', (m) => {
  const gianoAccountImplementation = m.contract('GianoSmartWallet');
  const gianoAccountFactory = m.contract('GianoSmartWalletFactory', [gianoAccountImplementation], { id: 'GianoSmartWalletFactoryV07' });

  const gianoAccountImplementationV08 = m.contract('GianoSmartWalletV08');
  const gianoAccountFactoryV08 = m.contract('GianoSmartWalletFactory', [gianoAccountImplementationV08], { id: 'GianoSmartWalletFactoryV08' });

  return { gianoAccountFactory, gianoAccountFactoryV08 };
});
