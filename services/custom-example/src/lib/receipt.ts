import { hexToBigInt, ZERO_ADDRESS, type Address } from './format';

/**
 * The receipt the wallet-api's public endpoint returns for `waitForUserOperationReceipt` — the
 * bundler's ERC-4337 `eth_getUserOperationReceipt` shape, hex-encoded. Typed here because the
 * connector returns `unknown` (finding G4).
 */
export type UserOpReceipt = {
  userOpHash?: string;
  sender?: string;
  nonce?: string;
  paymaster?: string;
  actualGasCost?: string;
  actualGasUsed?: string;
  success?: boolean;
  reason?: string;
  receipt?: {
    transactionHash?: string;
    blockNumber?: string;
    blockHash?: string;
    gasUsed?: string;
    status?: string;
  };
};

export type Payer = 'sponsored' | 'self-paid';

export type Attribution = {
  actualPayer: Payer | 'unknown';
  paymaster?: Address;
  actualGasCost?: bigint;
  /** Native balance delta of the sender across the operation, when both readings exist. */
  nativeDelta?: bigint;
  matchesDeclared?: boolean;
  note: string;
};

/**
 * Who paid, from evidence rather than intent (design.md D5): a non-zero `paymaster` on the receipt
 * means sponsored; otherwise the sender paid, and the native balance delta should roughly equal
 * `actualGasCost` (plus any value sent).
 */
export function attributePayer(receipt: UserOpReceipt | undefined, declared: Payer | undefined, before?: bigint, after?: bigint): Attribution {
  if (!receipt) return { actualPayer: 'unknown', note: 'no receipt' };
  const paymaster = receipt.paymaster && receipt.paymaster.toLowerCase() !== ZERO_ADDRESS ? (receipt.paymaster as Address) : undefined;
  const actualGasCost = hexToBigInt(receipt.actualGasCost);
  const nativeDelta = before !== undefined && after !== undefined ? after - before : undefined;
  const actualPayer: Payer = paymaster ? 'sponsored' : 'self-paid';
  const matchesDeclared = declared ? declared === actualPayer : undefined;
  const note = paymaster
    ? `sponsored by paymaster ${paymaster}${matchesDeclared === false ? ' — payer differs from declaration' : matchesDeclared ? ' — as declared' : ''}`
    : `paid by the account${actualGasCost !== undefined ? ` (${actualGasCost.toString()} wei gas)` : ''}${matchesDeclared === false ? ' — payer differs from declaration' : matchesDeclared ? ' — as declared' : ''}`;
  return { actualPayer, paymaster, actualGasCost, nativeDelta, matchesDeclared, note };
}
