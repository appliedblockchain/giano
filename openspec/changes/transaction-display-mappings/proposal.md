## Why

A Giano user approving a transaction today sees the target address, a native value labelled "ETH" whatever the chain, and, only when the calldata happens to match one of two hard-coded ABIs (ERC-20 and the Giano smart wallet), a raw `functionName(arg, arg)` string. Everything else is a hex blob. The user cannot validate what they are signing, which is the one thing the consent screen exists for. Tenants have no way to teach the wallet what their own contracts do.

Ticket H4 (3 SP, low priority) asks for a Giano-independent library that turns transaction data into human-readable information, a tenant-editable set of mappings served by wallet-api, and a wallet UI that shows raw data only when no mapping produces anything readable.

## What Changes

- **New package `packages/tx-describe`** (`@appliedblockchain/giano-tx-describe`): a pure library that takes a transaction (`to`, `value`, `data`, `chainId`) plus a set of mappings and returns a structured, human-readable description or an explicit "unknown" result. It depends on no Giano package (R1). Mappings use the ERC-7730 "clear signing" descriptor format, so one descriptor covers every call to a function on a contract, and tenants can reuse descriptors from the public ERC-7730 registry. The library ships built-in generic descriptors for the ERC-20 and ERC-721 standard functions and for a bare native transfer.
- **New tenant mappings in wallet-api**: a `tenant_tx_mappings` table (plus history), admin CRUD under `/v1/admin/tx-mappings` keyed by chain and contract, validated on write against the ERC-7730 schema, and a tenant-scoped read endpoint `/v1/tx-mappings` the wallet origin fetches at review time. OpenAPI document regenerated.
- **wallet-kit exposes `runtime.describeTransaction(tx)`**: fetches and caches the tenant's mappings for the runtime's chain, merges them with the library's built-ins, resolves ERC-20 token symbol and decimals through the runtime's public client, and returns the description. Bring-your-own wallet origins get the same capability without touching wallet-api themselves.
- **wallet-web review screen rewritten around the description**: shows an intent line ("Send 10.5 USDC to 0x1234…abcd"), labelled fields, and the correct native currency symbol for the chain. Raw calldata is shown only when the description is "unknown", together with a clear warning that the wallet cannot explain this transaction. The hard-coded two-ABI decode is removed.
- **e2e BYO wallet** demonstrates the kit method; Playwright asserts the intent line for the demo ERC-20 transfer in the stock wallet.
- Developer guide and integration docs gain a section on publishing tenant transaction mappings.

No breaking changes to published package surfaces: `PendingRequest` keeps its shape, `WalletRuntime` gains one method.

## Capabilities

### New Capabilities
- `transaction-description`: the library contract. Given a transaction and a set of ERC-7730 mappings, produce a human-readable description (intent, fields, warnings) or an explicit unknown result; selection by chain, contract and function selector; built-in generic descriptors; token formatting delegated to the caller.
- `tenant-transaction-mappings`: wallet-api storage and API. Tenant admins create, read, replace and delete per-chain, per-contract ERC-7730 mappings; every write is validated and recorded in history; the wallet origin reads the tenant's effective mapping set for a chain.
- `wallet-transaction-review`: what the wallet consent screen shows for a transaction. Human-readable description first, native currency named per chain, raw data only as a last resort and clearly labelled; the kit-level `describeTransaction` surface available to any wallet origin.

### Modified Capabilities
None. `openspec/specs/` is empty on `main`; the existing prose specs under `specs/*.md` are updated as documentation in the tasks, not as OpenSpec deltas.

## Impact

- **New code**: `packages/tx-describe` (library, tests), `services/wallet-api` (migration `0006_tx_mappings.sql`, schema, `services/tx-mappings.ts`, `routes/admin-tx-mappings.ts`, `routes/tx-mappings.ts`, tests), `packages/wallet-kit` (`runtimes.ts`, new `describe.ts`, tests), `services/wallet-web/src/views/ReviewTransaction.tsx`, `e2e/wallet-byo/src/views.ts`, `e2e/tests/wallet-flow.spec.ts`.
- **New external dependency**: `@ethereum-sourcify/clear-signing` (MIT, ERC-7730 formatting engine, only `@noble/hashes` at runtime) inside the new library. Falls under the repo's `minimumReleaseAge` supply-chain policy.
- **Release wiring**: the new package joins the changesets `fixed` group and the CI package build matrix. wallet-kit gains a dependency on the new package; wallet-web loses its direct import of `@appliedblockchain/giano-contracts` for decoding.
- **Database**: one additive migration, two new tables, no changes to existing tables.
- **APIs**: five new admin routes and one new tenant-scoped read route in wallet-api; `openapi/openapi.json` regenerated.
- **Docs**: `specs/DEVELOPER-GUIDE.md` (new section under Part C), `specs/INTEGRATION.md`, `specs/WALLET-SDK-SPECS.md` (runtime surface), `specs/TRANSACTION-SUBMISSION-FLOW.md` (review step).
- **Out of scope**: descriptions for `personal_sign` / typed-data requests, EIP-5792 batch requests (the connector does not expose them), a UI for tenants to edit mappings (admin API only, like sponsorship rules), ENS or address-book name resolution.
