## Purpose

Turns a transaction request (target, value, calldata, chain) plus a set of transaction mappings into a human-readable description a user can validate before signing, or into an explicit "unknown" result when no mapping explains it. Provided as a standalone library that any Giano service, and any non-Giano consumer, can use.

## ADDED Requirements

### Requirement: The library is independent of Giano
The library SHALL have no dependency on any other Giano package at build time or at runtime. It SHALL NOT perform network requests, read chain state, or access browser or Node globals beyond what is needed for pure computation. Everything it needs beyond the transaction itself (mappings, token metadata, the chain's native currency) SHALL be supplied by the caller.

#### Scenario: Dependency direction
- **WHEN** the library's declared dependencies and its compiled output are inspected
- **THEN** no `@appliedblockchain/giano-*` package appears among them, and no code path issues an HTTP or RPC request

#### Scenario: Usable outside a Giano service
- **WHEN** a consumer with no other Giano package installed calls the library with a transaction and a mapping set
- **THEN** it receives a description without needing any Giano runtime, configuration or service

### Requirement: Mappings use the ERC-7730 descriptor format
A mapping SHALL be an ERC-7730 (Structured Data Clear Signing Format) descriptor for a contract: it binds one or more `(chainId, contract address)` deployments and, for each function, a human-readable ABI fragment or a 4-byte selector, an intent, and the fields to display with their display formats. One descriptor therefore applies to every transaction that calls that function on that contract. The library SHALL expose a validation function that reports every violation with a JSON path and message, and SHALL accept both the human-readable signature form (`transfer(address to, uint256 value)`) and the raw selector form (`0xa9059cbb`) as function keys, normalising signatures to selectors internally.

#### Scenario: A valid descriptor is accepted
- **WHEN** a descriptor with a deployment binding, one function keyed by human-readable signature, an intent and at least one field is validated
- **THEN** validation reports no issues and the descriptor can be used for description

#### Scenario: An invalid descriptor is rejected with paths
- **WHEN** a descriptor is missing its deployment binding, or a field references a parameter path that does not exist in the function's ABI, or a function key is neither a signature nor a selector
- **THEN** validation reports one issue per violation, each with the JSON path of the offending element and a message, and the descriptor is not usable for description

#### Scenario: Signature and selector keys are equivalent
- **WHEN** two descriptors differ only in that one keys a function by `transfer(address to, uint256 value)` and the other by `0xa9059cbb`
- **THEN** both describe the same transaction identically, the selector-keyed one taking its parameter names from the inline ABI

### Requirement: A transaction is described by chain, contract and selector
Given a transaction `{ chainId, to, value, data }` and a mapping set, the library SHALL select the descriptor whose deployments include `(chainId, to)` and whose formats include the first four bytes of `data`, decode the calldata against that function's ABI, and return a description containing: a single intent sentence with field values interpolated, an ordered list of labelled fields, the contract address, the function signature or selector, the mapping source, and any warnings. Field values SHALL be rendered according to their declared format: addresses checksummed and shortenable, native amounts in the chain's currency units, token amounts scaled by the token's decimals with its symbol, timestamps as dates, enums as their labels, raw values as-is.

#### Scenario: A tenant-mapped call
- **WHEN** a transaction calls `0xa9059cbb` on a contract for which the mapping set has a descriptor on that chain, with intent "Send {value} to {to}" and `value` formatted as a token amount
- **THEN** the description's intent reads like "Send 10.5 USDC to 0x1234…abcd", its fields list "Amount" and "Recipient", its source is the tenant mapping and it carries no warnings

#### Scenario: The same mapping covers every call of that kind
- **WHEN** two different transactions call the same function on the same contract with different arguments
- **THEN** both are described by the one descriptor, differing only in the interpolated values

#### Scenario: A mapping for the same contract on another chain does not apply
- **WHEN** a descriptor binds a contract on chain A only and a transaction targets the same address on chain B
- **THEN** that descriptor is not selected for the chain B transaction

#### Scenario: Native value alongside a contract call
- **WHEN** a described contract call also carries a non-zero native `value`
- **THEN** the description includes an additional native-amount field in the chain's currency, so the value cannot go unnoticed

### Requirement: Built-in generic mappings for standard interfaces
The library SHALL ship generic descriptors, not bound to any contract address, for the ERC-20 functions `transfer`, `approve` and `transferFrom`, and the ERC-721 functions `transferFrom`, `safeTransferFrom` (both arities), `approve` and `setApprovalForAll`. They SHALL be used only when no caller-supplied descriptor matches, SHALL be reported with a distinct source of "generic", and SHALL carry a warning that the contract has not been confirmed to implement that interface. Callers SHALL be able to disable built-ins.

#### Scenario: Generic fallback
- **WHEN** a transaction calls `0x095ea7b3` (`approve(address,uint256)`) on a contract with no caller-supplied descriptor
- **THEN** the description's intent names an approval of an amount to a spender, its source is "generic", and its warnings include that the interface is assumed, not verified

#### Scenario: Caller mapping wins over built-in
- **WHEN** a caller-supplied descriptor and a built-in both match the same chain, contract and selector
- **THEN** the caller-supplied descriptor is used and the source is the caller's

#### Scenario: Built-ins disabled
- **WHEN** the caller disables built-ins and only built-ins would match
- **THEN** the result is unknown

### Requirement: Native transfers are described without a mapping
A transaction whose `data` is empty or `0x` SHALL be described as a native-currency transfer of `value` to `to`, using the native currency the caller supplies for the chain (defaulting to ETH with 18 decimals), without any mapping.

#### Scenario: Plain value transfer
- **WHEN** a transaction has `to`, `value` of 1.5 units and empty `data` on a chain whose native currency is supplied as "MATIC"
- **THEN** the intent reads like "Send 1.5 MATIC to 0x1234…abcd" and no warning is raised

### Requirement: Unknown transactions are reported explicitly, never guessed
When no descriptor (caller-supplied or built-in) matches, when decoding against the selected function's ABI fails, or when the transaction has no `to` (contract creation), the library SHALL return an explicit unknown result carrying the reason (`no-mapping`, `decode-failed`, `contract-creation`), the selector and contract when known, and the raw `to`, `value` and `data`. It SHALL NOT apply a descriptor for a different selector or contract, and SHALL NOT fall back to pretty-printing ABI arguments as if that were a description.

#### Scenario: No mapping matches
- **WHEN** a transaction calls a selector for which no descriptor exists on that chain and contract
- **THEN** the result is unknown with reason `no-mapping`, includes the selector and the raw fields, and includes no intent

#### Scenario: Calldata does not fit the mapped function
- **WHEN** a descriptor matches the selector but the calldata cannot be decoded against that function's parameter types
- **THEN** the result is unknown with reason `decode-failed` and the raw fields, so a malformed call is never shown as a plausible action

### Requirement: Token metadata is supplied by the caller
For fields formatted as token amounts, the library SHALL ask the caller for the token's symbol and decimals through an optional resolver. When no resolver is supplied, or it returns nothing, or it throws, the field SHALL still be rendered, as the raw integer amount with the token's address, and the description SHALL carry a warning that the amount is unscaled.

#### Scenario: Resolver answers
- **WHEN** the resolver returns `{ symbol: "USDC", decimals: 6 }` for the token
- **THEN** an amount of 10500000 renders as "10.5 USDC"

#### Scenario: Resolver missing or failing
- **WHEN** no resolver is supplied, or the resolver rejects
- **THEN** the amount renders as "10500000 (token 0x1234…abcd)" and the description warns that the token could not be resolved

### Requirement: Description is deterministic and bounded
For the same inputs the library SHALL return the same description. It SHALL complete without waiting on anything but the caller's resolver, and SHALL never throw for any transaction input; malformed input yields an unknown result.

#### Scenario: Garbage input
- **WHEN** `data` is not valid hex, or `value` is not a number-like value
- **THEN** the library returns an unknown result with reason `decode-failed` rather than throwing
