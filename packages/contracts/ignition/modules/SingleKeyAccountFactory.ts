import { buildModule } from '@nomicfoundation/hardhat-ignition/modules';
import { ethers } from 'ethers';

export default buildModule('SingleKeyAccountFactory', (m) => {

	const randomSalt = new Uint8Array(32);
	crypto.getRandomValues(randomSalt)
	const salt = m.getParameter('salt', ethers.hexlify(randomSalt))

  const singleKeyAccountFactory = m.contract('SingleKeyAccountFactory', [salt]);

  return { singleKeyAccountFactory };
});
