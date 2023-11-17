// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// You can also run a script with `npx hardhat run <script>`. If you do that, Hardhat
// will compile your contracts, add the Hardhat Runtime Environment's members to the
// global scope, and execute the script.
import hre from 'hardhat';

const [signer] = await hre.ethers.getSigners();

const contract = await hre.ethers.deployContract('Bank', { signer });
await contract.waitForDeployment();

if (contract.target !== '0x5FbDB2315678afecb367f032d93F642f64180aa3') {
  throw new Error('HRE deployment is supposed to be deterministic, but contract address is not the expect one!');
}

console.log(`Owner address: ${signer.address}`);
console.log(`Contract address: ${contract.target}`);
