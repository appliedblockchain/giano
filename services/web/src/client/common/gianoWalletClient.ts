import type { Account } from '@giano/contracts/typechain-types';
import { Account__factory } from '@giano/contracts/typechain-types';
import type { TypedContractMethod } from '@giano/contracts/typechain-types/common';
import type { BaseContract, BigNumberish, ContractRunner, ContractTransactionResponse } from 'ethers';

type SendTransactionProps = {
  value: BigNumberish;
};

export type ProxiedMethod<Inputs extends any[]> = (...args: Inputs) => {
  send(opts?: SendTransactionProps): Promise<ContractTransactionResponse>;
};

export type ProxiedContract<T extends BaseContract> = {
  [K in keyof T]: T[K] extends TypedContractMethod<infer Inputs, any, infer StateMutability>
    ? StateMutability extends 'view' | 'pure'
      ? T[K] // Keep view and pure methods as is
      : ProxiedMethod<Inputs> // Replace non-view methods with proxied methods
    : T[K]; // Keep other properties unchanged
};

export type WalletClient = {
  account: Account;
  proxyFor: <T extends BaseContract>(contract: T) => ProxiedContract<T>;
};

type GianoWalletClientParams = {
  address: string;
  signer: ContractRunner;
  challengeSigner: (challenge: string) => Promise<string>;
};

export const GianoWalletClient = function ({ address, signer, challengeSigner }: GianoWalletClientParams): WalletClient {
  const account = Account__factory.connect(address, signer);
  return {
    account,
    proxyFor: <T extends BaseContract>(contract: T): ProxiedContract<T> => {
      return new Proxy(contract, {
        get(target, prop) {
          const original = target[prop];
          if (typeof original === 'function' && typeof prop === 'string') {
            const contractFn = contract.getFunction(prop);
            if (!contractFn || contractFn?.fragment.stateMutability === 'view') {
              return original;
            }
          } else {
            return original;
          }
          const functionName = prop;
          return function (...args: any[]) {
            return {
              async send(props?: SendTransactionProps) {
                try {
                  const challenge = await account.getChallenge();
                  return await account.execute({
                    target: contract.target,
                    value: props?.value || 0n,
                    data: contract.interface.encodeFunctionData(functionName, args),
                    signature: await challengeSigner(challenge),
                  });
                } catch (err) {
                  const e: any = err;
                  if (e.code === 'CALL_EXCEPTION' && !e.revert && e.data) {
                    const parsed = contract.interface.parseError(e.data);
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
              },
            };
          };
        },
      }) as ProxiedContract<T>;
    },
  };
};
