import { createWalletClient } from 'viem';
import { mnemonicToAccount } from 'viem/accounts';
import type { SendTransactionFnParams } from '../connector';

export const hardhatDefaultAccountSender = async ({ chain, transport, request }: SendTransactionFnParams) => {
  const account = mnemonicToAccount('test test test test test test test test test test test junk');
  const client = createWalletClient({ transport, chain, account });

  const prepared = await client.prepareTransactionRequest(request);
  // TODO: investigate why Viem is underestimating the gas here
  const signed = await client.signTransaction({ ...prepared, gas: prepared.gas * 5n });
  return client.sendRawTransaction({ serializedTransaction: signed });
};
