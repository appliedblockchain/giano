import { buildModule } from '@nomicfoundation/hardhat-ignition/modules';

export default buildModule('GianoAccountFactory', (m) => {
  // Deploy V07 implementation (initial deployment target)
  const gianoAccountImplementationV07 = m.contract('GianoSmartWallet');
  
  // Deploy V08 implementation (upgrade target)
  const gianoAccountImplementationV08 = m.contract('GianoSmartWalletV08Implementation');
  
  // Deploy factory using V07 implementation (users start with V07)
  const gianoAccountFactory = m.contract('GianoSmartWalletFactory', [gianoAccountImplementationV07]);

  return { 
    // Primary deployments
    gianoAccountFactory,
    gianoAccountImplementationV07,
    gianoAccountImplementationV08,
    
    // For convenience in upgrade scripts
    v07Implementation: gianoAccountImplementationV07,
    v08Implementation: gianoAccountImplementationV08,
    factory: gianoAccountFactory
  };
});
