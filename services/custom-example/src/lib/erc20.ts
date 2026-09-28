import { erc20Abi } from 'viem';

export { erc20Abi };

/** Giano's test ERC-20 (`PrivateERC20`): anyone can mint to themselves; `privateBalanceOf` only answers the caller. */
export const testErc20Abi = [
  ...erc20Abi,
  { type: 'function', name: 'mint', stateMutability: 'nonpayable', inputs: [{ name: 'amount', type: 'uint256' }], outputs: [] },
  { type: 'function', name: 'privateBalanceOf', stateMutability: 'view', inputs: [{ name: 'account', type: 'address' }], outputs: [{ type: 'uint256' }] },
] as const;

/** EIP-2612 fragment: `nonces()` doubles as the probe for permit support. */
export const erc2612Abi = [
  { type: 'function', name: 'nonces', stateMutability: 'view', inputs: [{ name: 'owner', type: 'address' }], outputs: [{ type: 'uint256' }] },
  {
    type: 'function',
    name: 'permit',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'owner', type: 'address' },
      { name: 'spender', type: 'address' },
      { name: 'value', type: 'uint256' },
      { name: 'deadline', type: 'uint256' },
      { name: 'v', type: 'uint8' },
      { name: 'r', type: 'bytes32' },
      { name: 's', type: 'bytes32' },
    ],
    outputs: [],
  },
] as const;
