import type { Account } from '@giano/contracts/typechain-types';
import { Account__factory } from '@giano/contracts/typechain-types';
import type { Addressable, Contract, ContractRunner, Interface } from 'ethers';
import { ethers } from 'ethers';

type WalletClient = {
  account: Account;
  proxyFor: (iface: Interface, contractAddress: string | Addressable) => Contract;
};

const GianoWalletClient = (address: string, signer: ContractRunner): WalletClient => {
  const account = Account__factory.connect(address, signer);
  return {
    account,
    proxyFor: (iface: Interface, contractAddress: string | Addressable) => {
      const readInstance = new ethers.Contract(contractAddress, iface);
      return new Proxy(readInstance, {
        get(target, prop, receiver) {
          const functionName = prop.toString();
          return async function ({ args, signature }: { args: any[]; signature: Uint8Array }) {
            // // if it's a read-only function, relay to the actual contract directly to have access to the return value
            // if (['view', 'pure'].includes(iface.getFunction(functionName)?.stateMutability as string)) {
            //   return await Reflect.get(target, prop, receiver)(args);
            // }
            try {
              return await account.execute({
                target: contractAddress,
                value: 0n,
                data: iface.encodeFunctionData(functionName, args),
                signature,
              });
            } catch (err) {
              const e: any = err;
              if (e.code === 'CALL_EXCEPTION' && !e.revert && e.data) {
                const parsed = iface.parseError(e.data);
                if (parsed) {
                  const { name, signature, args } = parsed;
                  e.revert = {
                    name,
                    signature,
                    args,
                  };
                  e.reason = signature;
                  e.message = `execution reverted: ${e.reason}`;
                }
              }
              throw e;
            }
          };
        },
      });
    },
  };
};

export { GianoWalletClient, type WalletClient };
