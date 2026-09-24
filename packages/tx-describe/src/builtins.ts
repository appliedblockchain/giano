import type { Mapping } from './types';
import { functionSelector } from './signature';

/**
 * Generic mappings for the ERC-20 and ERC-721 interfaces, matched by selector alone.
 *
 * They are templates: `deploymentsOf` is empty until `bindBuiltin` binds one to the chain and
 * contract of the transaction being described. A description produced from one is reported
 * with source `generic` and a `generic-interface` warning, because a matching selector proves
 * nothing about the contract — see the spec's "Built-in generic mappings" requirement.
 *
 * `approve(address,uint256)` and `transferFrom(address,address,uint256)` have the same
 * selector in both standards. They are described once, with the third argument as a token
 * amount: on an ERC-20 the caller's token resolver scales it; on an ERC-721 `decimals()`
 * does not exist, the resolver returns nothing, and the value is shown unscaled — which for a
 * token id is the right rendering, and the `token-unresolved` warning says why.
 */

const abi = {
  transfer: { type: 'function', name: 'transfer', stateMutability: 'nonpayable', inputs: [{ name: 'to', type: 'address' }, { name: 'value', type: 'uint256' }], outputs: [] },
  approve: { type: 'function', name: 'approve', stateMutability: 'nonpayable', inputs: [{ name: 'spender', type: 'address' }, { name: 'value', type: 'uint256' }], outputs: [] },
  transferFrom: { type: 'function', name: 'transferFrom', stateMutability: 'nonpayable', inputs: [{ name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' }], outputs: [] },
  safeTransferFrom3: { type: 'function', name: 'safeTransferFrom', stateMutability: 'nonpayable', inputs: [{ name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'tokenId', type: 'uint256' }], outputs: [] },
  safeTransferFrom4: { type: 'function', name: 'safeTransferFrom', stateMutability: 'nonpayable', inputs: [{ name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'tokenId', type: 'uint256' }, { name: 'data', type: 'bytes' }], outputs: [] },
  setApprovalForAll: { type: 'function', name: 'setApprovalForAll', stateMutability: 'nonpayable', inputs: [{ name: 'operator', type: 'address' }, { name: 'approved', type: 'bool' }], outputs: [] },
} as const;

const tokenAmount = (path: string, label: string) => ({ path, label, format: 'tokenAmount' as const, params: { tokenPath: '@.to' } });
const address = (path: string, label: string) => ({ path, label, format: 'addressName' as const });
const raw = (path: string, label: string) => ({ path, label, format: 'raw' as const });

const templates = [
  {
    metadata: { contractName: 'Token (ERC-20 interface)' },
    context: { contract: { deployments: [], abi: [abi.transfer, abi.approve, abi.transferFrom] } },
    display: {
      formats: {
        'transfer(address to, uint256 value)': {
          intent: 'Send tokens',
          interpolatedIntent: 'Send {value} to {to}',
          fields: [tokenAmount('value', 'Amount'), address('to', 'Recipient')],
        },
        'approve(address spender, uint256 value)': {
          intent: 'Approve token spending',
          interpolatedIntent: 'Allow {spender} to spend {value}',
          fields: [address('spender', 'Spender'), tokenAmount('value', 'Amount')],
        },
        'transferFrom(address from, address to, uint256 value)': {
          intent: 'Transfer tokens on behalf of another account',
          interpolatedIntent: 'Transfer {value} from {from} to {to}',
          fields: [tokenAmount('value', 'Amount'), address('from', 'From'), address('to', 'Recipient')],
        },
      },
    },
  },
  {
    metadata: { contractName: 'Collectible (ERC-721 interface)' },
    context: { contract: { deployments: [], abi: [abi.safeTransferFrom3, abi.safeTransferFrom4, abi.setApprovalForAll] } },
    display: {
      formats: {
        'safeTransferFrom(address from, address to, uint256 tokenId)': {
          intent: 'Transfer a collectible',
          interpolatedIntent: 'Transfer collectible #{tokenId} from {from} to {to}',
          fields: [raw('tokenId', 'Token ID'), address('from', 'From'), address('to', 'Recipient')],
        },
        'safeTransferFrom(address from, address to, uint256 tokenId, bytes data)': {
          intent: 'Transfer a collectible',
          interpolatedIntent: 'Transfer collectible #{tokenId} from {from} to {to}',
          fields: [raw('tokenId', 'Token ID'), address('from', 'From'), address('to', 'Recipient'), raw('data', 'Attached data')],
        },
        'setApprovalForAll(address operator, bool approved)': {
          intent: 'Change operator approval for all collectibles',
          interpolatedIntent: 'Set {operator} as operator for all your collectibles: {approved}',
          fields: [address('operator', 'Operator'), raw('approved', 'Approved')],
        },
      },
    },
  },
] as unknown as Mapping[];

const bySelector = new Map<string, Mapping>();
for (const template of templates) {
  for (const key of Object.keys(template.display!.formats!)) bySelector.set(functionSelector(key), template);
}

/** The built-in template covering a selector, if any. Unbound: see `bindBuiltin`. */
export function builtinFor(selector: string): Mapping | undefined {
  return bySelector.get(selector.toLowerCase());
}

/** A copy of a template bound to one chain and contract, ready for the engine. */
export function bindBuiltin(template: Mapping, chainId: number, contract: string): Mapping {
  return {
    ...template,
    context: {
      ...template.context,
      contract: { ...template.context!.contract!, deployments: [{ chainId, address: contract.toLowerCase() }] },
    },
  };
}

/** Selectors the built-ins cover, for documentation and tests. */
export const BUILTIN_SELECTORS: readonly string[] = [...bySelector.keys()];
