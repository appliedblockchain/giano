# @appliedblockchain/giano-tx-describe

Turns a transaction request into something a person can validate before signing, or says plainly that it cannot.

```ts
import { describeTransaction } from '@appliedblockchain/giano-tx-describe';

const description = await describeTransaction(
  { chainId: 8453, to: usdc, data: calldata, value: 0n },
  { mappings: tenantMappings, resolveToken, nativeCurrency: { symbol: 'ETH', decimals: 18 } },
);

if (description.kind === 'described') {
  description.intent;   // "Send 10.5 USDC to 0x1234…abcd"
  description.fields;   // [{ label: 'Amount', value: '10.5 USDC', kind: 'token-amount', address }, …]
  description.source;   // 'mapping' | 'generic' | 'native'
  description.warnings; // [{ code: 'generic-interface' | 'token-unresolved' | …, message }]
} else {
  description.reason;   // 'no-mapping' | 'decode-failed' | 'contract-creation'
  description.raw;      // { to, value, data } — the only thing left to show
}
```

## Independence

This package depends on nothing else in Giano and performs no I/O: no RPC, no HTTP, no chain reads. Everything it needs beyond the transaction is supplied by the caller: the mappings, the chain's native currency, and an optional token resolver for symbols and decimals. Any service, Giano or not, can use it; `test/independence.test.ts` enforces the dependency direction.

## Mappings are ERC-7730 descriptors

A mapping is an [ERC-7730 Clear Signing descriptor](https://eips.ethereum.org/EIPS/eip-7730) for one contract. Its deployments bind `(chainId, address)`; its formats explain each function, keyed by human-readable signature or 4-byte selector. One descriptor covers every call of a function on that contract, so a tenant writes one entry per contract, not per transaction. Descriptors from the [public registry](https://github.com/ethereum/clear-signing-erc7730-registry) work once their ABI is inlined.

Two restrictions keep the library offline: `context.contract.abi` must be an inline array (not a URL), and `includes` is refused (inline the included descriptor). `validateMapping` reports every violation with a JSON path:

```ts
import { validateMapping } from '@appliedblockchain/giano-tx-describe';

const result = validateMapping(json);
// { ok: false, issues: [{ path: 'display.formats.transfer(address to, uint256 value).fields[1].path',
//                          message: '"recipient" does not name an input of transfer(address,uint256) (inputs: to, value)' }] }
```

A complete ERC-20 example:

```json
{
  "$schema": "https://eips.ethereum.org/assets/eip-7730/erc7730-v1.schema.json",
  "context": {
    "contract": {
      "deployments": [{ "chainId": 8453, "address": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913" }],
      "abi": [
        { "type": "function", "name": "transfer", "stateMutability": "nonpayable",
          "inputs": [{ "name": "to", "type": "address" }, { "name": "value", "type": "uint256" }], "outputs": [{ "name": "", "type": "bool" }] },
        { "type": "function", "name": "approve", "stateMutability": "nonpayable",
          "inputs": [{ "name": "spender", "type": "address" }, { "name": "value", "type": "uint256" }], "outputs": [{ "name": "", "type": "bool" }] }
      ]
    }
  },
  "metadata": { "owner": "Circle", "contractName": "USD Coin" },
  "display": {
    "formats": {
      "transfer(address to, uint256 value)": {
        "intent": "Send USDC",
        "interpolatedIntent": "Send {value} to {to}",
        "fields": [
          { "path": "value", "label": "Amount", "format": "tokenAmount", "params": { "tokenPath": "@.to" } },
          { "path": "to", "label": "Recipient", "format": "addressName" }
        ]
      },
      "approve(address spender, uint256 value)": {
        "intent": "Approve USDC spending",
        "interpolatedIntent": "Allow {spender} to spend {value}",
        "fields": [
          { "path": "spender", "label": "Spender", "format": "addressName" },
          { "path": "value", "label": "Amount", "format": "tokenAmount", "params": { "tokenPath": "@.to" } }
        ]
      }
    }
  }
}
```

Field paths address the function's inputs by name (`value`, `to`), the call container (`@.to`, `@.value`, `@.from`) or descriptor metadata (`$.metadata.…`). Formats: `raw`, `amount` (native currency), `tokenAmount`, `addressName`, `date`, `duration`, `unit`, `enum`, `chainId`, `nftName`, `tokenTicker`.

## How a transaction is described

1. No `to`: `unknown` / `contract-creation`.
2. Empty `data`: a native transfer, described without any mapping (`source: 'native'`).
3. The first caller mapping whose deployments include `(chainId, to)` **and** whose formats include the selector is used (`source: 'mapping'`).
4. Otherwise, a built-in generic mapping matched by selector alone: ERC-20 `transfer`, `approve`, `transferFrom`; ERC-721 `safeTransferFrom` (both arities), `setApprovalForAll` (`approve` and `transferFrom` share selectors with ERC-20 and are described once). The result is `source: 'generic'` with a `generic-interface` warning, because a selector proves nothing about the contract. Pass `builtins: false` to turn this off.
5. Nothing matched: `unknown` / `no-mapping`, with selector, contract and raw fields. Calldata that does not fit the matched function: `unknown` / `decode-failed`. The library never pretty-prints ABI arguments as if that were a description, and never throws.

A described call that also carries native value gains a `Value` field unless the mapping already displays `@.value`.

## Token metadata

For `tokenAmount` fields the caller's `resolveToken(chainId, address)` supplies `{ symbol, decimals }`. When it is absent, returns `null` or rejects, the amount is shown unscaled as `"10500000 (token 0x1234…abcd)"` and the description carries a `token-unresolved` warning.

## Engine

Formatting is done by [`@ethereum-sourcify/clear-signing`](https://github.com/sourcifyeth/clear-signing) (MIT, one runtime dependency), wrapped in `src/engine.ts`, the only module that imports it. Descriptors are handed to it in memory; nothing is fetched.
