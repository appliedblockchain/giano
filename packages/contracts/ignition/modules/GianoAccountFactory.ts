import { buildModule } from '@nomicfoundation/hardhat-ignition/modules';

export default buildModule('GianoAccountFactory', (m) => {
  const gianoAccountImplementation = m.contract('CoinbaseSmartWallet');
  const gianoAccountFactory = m.contract('CoinbaseSmartWalletFactory', [gianoAccountImplementation]);

  return { gianoAccountFactory };
});
