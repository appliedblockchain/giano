import { buildModule } from '@nomicfoundation/hardhat-ignition/modules';
import { ethers } from 'ethers';

export default buildModule('SingleKeyAccountFactory', (m) => {
  const factorySalt = m.getParameter('factorySalt', ethers.ZeroHash);
  
  const singleKeyAccountFactory = m.contract('SingleKeyAccountFactory', [factorySalt]);
  
  return { singleKeyAccountFactory };
});
