import { ethers, type Log } from 'ethers';
// import PasskeyArtifact from '../../artifacts/contracts/Passkey.sol/Passkey.json' assert { type: 'json' };
import { Passkey__factory } from '../../typechain-types';

const toWei = (num) => ethers.parseEther(num.toString());
const fromWei = (num) => ethers.formatEther(num);

const provider = new ethers.WebSocketProvider('ws://localhost:8545');
const account1 = new ethers.Wallet('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', provider); // 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
const account2 = new ethers.Wallet('0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d', provider); // 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
const passkey = new ethers.Contract('0x5FbDB2315678afecb367f032d93F642f64180aa3', Passkey__factory.abi, account1);
const ipasskey = new ethers.Interface(Passkey__factory.abi);

void passkey.on('*', (...args) => {
  console.log(args);
  // event.removeListener();
});

const getBalance = async (address) => {
  const balanceInWei = await provider.getBalance(address);
  return balanceInWei;
};

const sendTransaction = async () => {
  const nonce = await provider.getTransactionCount(account1.address, 'latest');

  await account1.sendTransaction({
    to: account2.address,
    value: ethers.parseUnits('1', 'ether'),
    nonce,
  });

  const senderBalance = await getBalance(account1.address);
  const receiverBalance = await getBalance(account2.address);
  console.log('Balances:', fromWei(senderBalance), fromWei(receiverBalance));
};

const verify = async (publicKey: string, signature: string, authenticatorData: string, clientDataJSON: string) => {
  console.log('Verification on the blockchain...');
  const tx = await passkey.parseAndVerifyPassKeySignature(publicKey, signature, authenticatorData, clientDataJSON);
  const receipt = await tx.wait();
  const blabla = receipt.logs.map((log) => ipasskey.parseLog(log));
  console.log(blabla);
  //const events = receipt.logs.map((log) => ipasskey.parseLog(log)).filter((log) => log.name === 'SignatureVerified');
  //console.log('Verification events', events);
  // const result = events[2].args;
  // console.log('Verification:', result);
  // return result;

  // expect(log.fragment.name).to.equal('SignatureVerified');
  // expect(log.args[0]).to.equal(ethers.solidityPackedKeccak256(['string'], [publicKey]));
  // expect(log.args[1]).to.equal(ethers.solidityPackedKeccak256(['string'], [signature]));
  // expect(log.args[2]).to.equal(false);
};

export default verify;
