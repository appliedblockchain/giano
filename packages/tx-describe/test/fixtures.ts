import type { Mapping } from '../src/index';

export const CHAIN = 31337;
export const USDC = '0x1111111111111111111111111111111111111111';
export const RECIPIENT = '0x2222222222222222222222222222222222222222';
export const SPENDER = '0x3333333333333333333333333333333333333333';
export const OTHER = '0x4444444444444444444444444444444444444444';

const word = (hex: string) => hex.replace(/^0x/, '').padStart(64, '0');
export const addressWord = (address: string) => word(address);
export const uintWord = (n: bigint) => word(n.toString(16));

export const SEL = {
  transfer: '0xa9059cbb',
  approve: '0x095ea7b3',
  transferFrom: '0x23b872dd',
  safeTransferFrom3: '0x42842e0e',
  safeTransferFrom4: '0xb88d4fde',
  setApprovalForAll: '0xa22cb465',
  deposit: '0xd0e30db0',
  unknown: '0xdeadbeef',
};

export const transferData = (to: string, amount: bigint) => `${SEL.transfer}${addressWord(to)}${uintWord(amount)}`;
export const approveData = (spender: string, amount: bigint) => `${SEL.approve}${addressWord(spender)}${uintWord(amount)}`;
export const transferFromData = (from: string, to: string, amount: bigint) => `${SEL.transferFrom}${addressWord(from)}${addressWord(to)}${uintWord(amount)}`;
export const safeTransferFromData = (from: string, to: string, id: bigint) => `${SEL.safeTransferFrom3}${addressWord(from)}${addressWord(to)}${uintWord(id)}`;
export const setApprovalForAllData = (operator: string, approved: boolean) => `${SEL.setApprovalForAll}${addressWord(operator)}${uintWord(approved ? 1n : 0n)}`;

export const erc20Abi = [
  { type: 'function', name: 'transfer', stateMutability: 'nonpayable', inputs: [{ name: 'to', type: 'address' }, { name: 'value', type: 'uint256' }], outputs: [{ name: '', type: 'bool' }] },
  { type: 'function', name: 'approve', stateMutability: 'nonpayable', inputs: [{ name: 'spender', type: 'address' }, { name: 'value', type: 'uint256' }], outputs: [{ name: '', type: 'bool' }] },
];

/** A tenant descriptor for USDC on the devnet: covers transfer only. */
export const usdcMapping = (overrides: Partial<Mapping> = {}): Mapping => ({
  $schema: 'https://eips.ethereum.org/assets/eip-7730/erc7730-v1.schema.json',
  context: { contract: { deployments: [{ chainId: CHAIN, address: USDC }], abi: erc20Abi } },
  metadata: { owner: 'Acme', contractName: 'USD Coin' },
  display: {
    formats: {
      'transfer(address to, uint256 value)': {
        intent: 'Send USDC',
        interpolatedIntent: 'Send {value} to {to}',
        fields: [
          { path: 'value', label: 'Amount', format: 'tokenAmount', params: { tokenPath: '@.to' } },
          { path: 'to', label: 'Recipient', format: 'addressName' },
        ],
      },
    },
  },
  ...overrides,
});

export const resolveUsdc = async () => ({ symbol: 'USDC', decimals: 6, name: 'USD Coin' });
