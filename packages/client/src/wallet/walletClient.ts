import type { Account } from '@appliedblockchain/giano-contracts';
import { Account__factory } from '@appliedblockchain/giano-contracts';
import type { BaseContract, BigNumberish, ContractRunner, ContractTransactionResponse } from 'ethers';

type SendTransactionProps = {
  value: BigNumberish;
};

type ExcludeBaseContractMethods<T> = Omit<T, keyof BaseContract>;

export type ProxiedContract<T extends BaseContract> = {
  [K in keyof ExcludeBaseContractMethods<T>]: T[K] extends (...args: infer Args) => any
    ? (...args: Args) => {
        send(): Promise<ContractTransactionResponse>;
      }
    : T[K];
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
                const fnData = contract.interface.encodeFunctionData(functionName, args);
                try {
                  const challenge = await account.getChallenge({ target: contract.target, value: props?.value || 0, data: fnData });
                  return await account.execute({
                    call: {
                      target: contract.target,
                      value: props?.value || 0n,
                      data: fnData,
                    },
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
