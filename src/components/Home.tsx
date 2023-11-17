import type { ReactNode } from 'react';
import React from 'react';
import { NavLink } from 'react-router-dom';
import { startAuthentication } from '@simplewebauthn/browser';
import { ethers } from 'ethers';
import BankArtifact from '../../artifacts/contracts/Bank.sol/Bank.json' assert { type: 'json' };
import { safeByteDecode, safeByteEncode } from '../helpers';

const toWei = (num) => ethers.parseEther(num.toString());
const fromWei = (num) => ethers.formatEther(num);

const provider = new ethers.WebSocketProvider('ws://localhost:8545');
const account1 = new ethers.Wallet('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', provider); // 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
const account2 = new ethers.Wallet('0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d', provider); // 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
const bank = new ethers.Contract('0x5FbDB2315678afecb367f032d93F642f64180aa3', BankArtifact.abi, account1);
const ibank = new ethers.Interface(BankArtifact.abi);

void bank.on('*', (...args) => {
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

const Home: React.FC = () => {
  const [registerResult, setRegisterResult] = React.useState<any>();
  const [depositResult, setDepositResult] = React.useState<any>();
  const [balance, setBalance] = React.useState<string>('');
  const [holders, setHolders] = React.useState<any>({});

  React.useEffect(() => {
    void checkBalance();
    void checkHolders();
  }, []);

  const checkBalance = async () => {
    const balance = await getBalance(account1.address);
    setBalance(fromWei(balance));
  };

  const checkHolders = async () => {
    const holdersCount = await bank.holdersCount();
    const holders = {};
    for (let counter = 0; counter < parseInt(holdersCount); counter++) {
      const holder = await bank.holders(counter);
      const balance = await bank.getBalance(holder);
      holders[holder] = parseInt(balance);
    }

    setHolders(holders);
  };

  // ref: https://www.smashingmagazine.com/2023/10/passkeys-explainer-future-password-less-authentication/#asserting-yourself
  const signTest = async (event) => {
    event.preventDefault();
    await sign('ciao');
  };

  const sign = async (args) => {
    // sign the challenge
    const credential = await navigator.credentials.get({
      publicKey: {
        challenge: new TextEncoder().encode('ciaone'),
        rpId: window.location.host,
        timeout: 60_000,
        // todo: add allowCredentials to narrow authenticator to registered one (ref: https://www.w3.org/TR/webauthn/#sctn-usecase-authentication)
      },
      mediation: 'optional',
    });

    const assertion = credential.response as AuthenticatorAssertionResponse;
    const signature = safeByteEncode(assertion.signature);
    console.log('Signature:', signature);
  };

  const register = async (event) => {
    console.log('Register');
    event.preventDefault();

    const tx = await bank.register();
    const receipt = await tx.wait();
    const events = receipt.logs.map((log) => ibank.parseLog(log)).filter((log) => log.name === 'Registration');
    const result = events[0].args;
    console.log('Registration', result);

    await checkBalance();
    await checkHolders();
  };

  const deposit = async (event) => {
    event.preventDefault();
    const formData = Object.fromEntries(new FormData(event.target)) as unknown as { holder: string; amount: number };
    console.log(formData);
  };

  return (
    <>
      <div className="absolute right-4 top-4 flex flex-row items-center gap-4">
        <p className="inline">Welcome!</p>
        <NavLink className="link-primary link" to={'/register'}>
          Logout
        </NavLink>
      </div>

      <main className="flex flex-row gap-4">
        <div className="paper m-auto mt-14 w-max">
          <h2 className="mb-4 text-2xl">Transaction test</h2>

          <div className="prose">
            <span>
              The contract <strong>Bank</strong> used is a dummy contract where user can perform 2 operations:
            </span>
            <ul>
              <li>register () public returns (bool)</li>
              <li>deposit (string memory signature, address authorizedAddress, uint256 amount) public returns (bool)</li>
            </ul>
          </div>

          <hr />

          <form className="my-4 flex flex-col gap-4" onSubmit={signTest}>
            <h2 className="text-2xl">Sign</h2>
            <p>This operation generates a random signature.</p>
            <button className="btn w-max">Sign</button>
          </form>

          <hr className="mb-4" />

          <form className="my-4 flex flex-col gap-4" onSubmit={register}>
            <h2 className="text-2xl">Register</h2>
            <p>
              <span className="block">This operation registers the provided address as a deposit holder.</span>
              <span className="block">This operation requires not parameter.</span>
            </p>

            <button className="btn w-max">Send tx</button>
          </form>

          <hr className="mb-4" />

          <form className="my-4 flex flex-col gap-4" onSubmit={deposit}>
            <h2 className="text-2xl">Deposit</h2>
            <p>
              <span className="block">This operation sums an amount to the a holder deposit.</span>
              <span className="block">This operation requires an address and an amount.</span>
            </p>

            <div className="form-control w-full max-w-xs">
              <label className="label">
                <span className="label-text">Holder</span>
              </label>
              <input name="holder" type="text" className="input input-bordered w-full max-w-xs" defaultValue="abc" />
            </div>
            <div className="form-control w-full max-w-xs">
              <label className="label">
                <span className="label-text">Amount</span>
              </label>
              <input name="amout" type="number" className="input input-bordered w-full max-w-xs" defaultValue="5" />
            </div>
            <button className="btn w-max">Send tx</button>
          </form>
        </div>

        <div className="paper m-auto mt-14 w-max">
          <h2 className="text-lg font-bold">Debugger</h2>

          <div className="flex flex-col gap-2">
            <div className="form-control w-max">
              <label className="label">
                <span className="label-text">Address</span>
              </label>
              <input name="address" className="input input-bordered w-[425px]" readOnly={true} value={account1.address} />
            </div>

            <div className="form-control w-max">
              <label className="label">
                <span className="label-text">Balance</span>
              </label>
              <input name="sender_balance" className="input input-bordered w-64" readOnly={true} value={balance} />
            </div>

            <div className="form-control w-max">
              <label className="label">
                <span className="label-text">Holders</span>
              </label>
              <div className="prose">
                <ul>
                  {Object.entries(holders).map(([holder, balance]) => (
                    <li key={holder}>
                      {holder}: {balance as ReactNode}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </div>
      </main>
    </>
  );
};

export default Home;
