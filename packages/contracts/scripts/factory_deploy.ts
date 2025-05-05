import type { TransactionResponse } from 'ethers';
import { keccak256 } from 'ethers';
import hre, { ethers } from 'hardhat';

// Standard CREATE2 factory deployed at the same address on all EVM chains
const FACTORY_DEPLOYER = '0x3fab184622dc19b6109349b94811493bf2a45362';
const FACTORY_ADDRESS = '0x4e59b44847b379578588920ca78fbf26c0b4956c';

// Salt to use for deploying SingleKeyAccountFactory (can be customized)
const FACTORY_SALT = ethers.ZeroHash;

async function reportGas(name: string, tx: TransactionResponse) {
  const receipt = await tx.wait();
  if (receipt) {
    const actualGasPaid = receipt.gasPrice * receipt.gasUsed;
    console.log(`${name} Deployed. Cost:`, ethers.formatEther(actualGasPaid));
  }
}

async function main() {
  console.log(`Network name: ${hre.network.name}`);
  console.log(`Chain ID: ${(await ethers.provider.getNetwork()).chainId}`);

  const [signer] = await ethers.getSigners();

  // Check if the CREATE2 factory exists, deploy it if not
  const factoryBytecode = await ethers.provider.getCode(FACTORY_ADDRESS);
  if (factoryBytecode === '0x') {
    console.log('CREATE2 factory not found; deploying...');
    // Fund the factory deployer
    await (await signer.sendTransaction({ to: FACTORY_DEPLOYER, value: ethers.parseEther('0.1') })).wait();

    // Deploy the CREATE2 factory
    const factoryDeployTx = await ethers.provider.broadcastTransaction(
      '0xf8a58085174876e800830186a08080b853604580600e600039806000f350fe7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf31ba02222222222222222222222222222222222222222222222222222222222222222a02222222222222222222222222222222222222222222222222222222222222222',
    );
    await reportGas('Factory', factoryDeployTx);
  } else {
    console.log('CREATE2 factory found');
  }

  // Generate a deterministic salt
  const salt = keccak256(ethers.toUtf8Bytes('SingleKeyAccountFactory-v1'));

  // Deploy the SingleKeyAccountFactory contract
  const SingleKeyAccountFactory = await ethers.getContractFactory('SingleKeyAccountFactory');

  // Compute the deterministic address where the contract will be deployed
  const initCodeHash = ethers.keccak256(ethers.concat([SingleKeyAccountFactory.bytecode, SingleKeyAccountFactory.interface.encodeDeploy([FACTORY_SALT])]));

  const predictedAddress = ethers.getCreate2Address(FACTORY_ADDRESS, salt, initCodeHash);

  console.log('Predicted SingleKeyAccountFactory address:', predictedAddress);

  // Check if the contract already exists at the predicted address
  const contractBytecode = await ethers.provider.getCode(predictedAddress);
  if (contractBytecode === '0x') {
    console.log('SingleKeyAccountFactory not found; deploying...');

    // Encode the bytecode with constructor parameters
    const factorySaltBytes32 = FACTORY_SALT;
    const bytecode = ethers.concat([SingleKeyAccountFactory.bytecode, SingleKeyAccountFactory.interface.encodeDeploy([factorySaltBytes32])]);

    // Deploy using CREATE2 factory
    const deployData = ethers.concat([salt, bytecode]);
    const deployTx = await signer.sendTransaction({
      to: FACTORY_ADDRESS,
      data: deployData,
      value: 0,
    });

    await reportGas('SingleKeyAccountFactory', deployTx);
    console.log('SingleKeyAccountFactory deployed at:', predictedAddress);
  } else {
    console.log('SingleKeyAccountFactory already deployed at:', predictedAddress);
  }
}

void main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
