## Context

See proposal.md for motivation. What shapes the approach:

- The consent screen receives the application's own `eth_sendTransaction` params (`to`, `value`, `data`), not the smart account's `execute` wrapper; the wrapping happens later in wallet-core when the user operation is built. So the UI describes one plain call. Batch requests (EIP-5792) are not exposed by the connector.
- `services/wallet-web/src/views/ReviewTransaction.tsx` already gates approval on the sponsorship pre-flight (WK-13 to WK-15) and decodes against two hard-coded ABIs; that decode goes away.
- Tenant sponsorship rules (`services/wallet-api/src/services/sponsorship-config.ts`) already give tenants a `(contract, selector)` vocabulary, normalising human-readable signatures to selectors on write, with full-replace PUT, validation-on-write, per-chain rows and a history table written by admin-key hash. The mappings API mirrors that shape.
- The kit is headless and the stock wallet is "pixels only" (WK-30): orchestration belongs in `@appliedblockchain/giano-wallet-kit`, not in wallet-web.
- R1: the library must depend on no Giano package. The dependency graph therefore runs library → kit → wallet-web, and wallet-api depends on the library for validation only.
- Open-source check (ticket suggestion). ERC-7730 is the standard for exactly this problem, with a public descriptor registry (`ethereum/clear-signing-erc7730-registry`). Two TypeScript engines exist:
  - `@ethereum-sourcify/clear-signing` 0.2.2 (July 2026), MIT, runtime dependency only `@noble/hashes`, ESM+CJS+types, pure formatting with an `ExternalDataProvider` for token/ENS data, `format()` and `formatTypedData()` return `intent`, `fields`, `interpolatedIntent`.
  - `@erc7730/sdk` 0.3.0 (September 2026), MIT, depends on `abitype`, `ajv`, `ajv-formats`, optional viem peer, 0 stars, three releases in the last week.
  - Hand-rolled with viem: `parseAbiItem` + `decodeFunctionData` + a small template interpolator is roughly 200 lines, but it would be a private format with no registry to draw on.

## Goals / Non-Goals

**Goals:**
- One mapping format (ERC-7730) shared by the library, the API and the docs, so a tenant can copy a registry descriptor and publish it unchanged.
- Description logic runs in the kit so stock and BYO wallets behave the same.
- Nothing about description can block or break consent: every failure degrades to warnings or an explicit unknown.
- Additive database change, no change to existing tables or published API shapes.

**Non-Goals:**
- Signing-request descriptions (`personal_sign`, typed data). ERC-7730 covers EIP-712 and the engine supports it; deferred to keep the change at its 3 SP.
- A tenant UI for authoring mappings. Admin API only, like sponsorship rules.
- ENS or address-book names. `addressName` fields render as checksummed shortened addresses.
- Verifying that a contract implements the interface a generic mapping assumes.

## Decisions

### D1 — Mapping format is ERC-7730, not a bespoke `(contract, selector, template)` record
ERC-7730 descriptors are keyed exactly the way the ticket asks: deployments bind `(chainId, address)`, formats bind a function by signature or selector, and one descriptor covers every call of that function. It adds what a bespoke format would have had to grow anyway: field display formats (`tokenAmount`, `amount`, `addressName`, `date`, `enum`, `raw`), intents with interpolation, and metadata. The public registry already holds descriptors for common tokens and protocols. Alternative: a minimal `{ contract, functions: [{ signature, intent, fields }] }` record mirroring the paymaster allowlist. Rejected because it would be a private format tenants have to learn and Giano has to maintain, with no registry to reuse; the allowlist's `(contract, selector)` shape is preserved as the *key*, which is what matters for administration.

### D2 — Engine: `@ethereum-sourcify/clear-signing` behind an internal adapter, with a spike gate
Chosen over `@erc7730/sdk` for its smaller dependency surface (one noble package versus `ajv` plus `abitype`), longer release history, and the explicit "pure formatting, external data delegated" design that matches R1. Both are pre-1.0, so the library wraps the engine in one adapter module (`src/engine.ts`) that exposes only what Giano needs: validate a descriptor, select by `(chainId, to, selector)`, format one call with a token resolver. Nothing outside that module imports the engine. Version pinned exactly (the repo already pins `zod` and `viem` exactly).

The first task is a spike with a pass/fail bar: the engine must accept caller-supplied descriptors with no network lookup, validate them with path-addressed issues, format the seven built-in functions and a tenant descriptor in tests, and respect the supply-chain policy (`minimumReleaseAge` 24h, satisfied). If it fails the bar, the adapter is implemented in-house against the ERC-7730 subset the specs need (`raw`, `amount`, `tokenAmount`, `addressName`, `date`, `enum`; no nested `calldata`), using `viem` as a peer dependency, and the descriptor JSON schema from the EIP is vendored for validation. The specs and the rest of the tasks are unchanged either way.

### D3 — Built-in generic mappings live in the library and are marked as such
The library ships descriptors for ERC-20 `transfer`, `approve`, `transferFrom` and ERC-721 `transferFrom`, `safeTransferFrom` (3 and 4 args), `approve`, `setApprovalForAll`, bound to no address. The selector matches; the contract is unverified, so the result is `source: 'generic'` with a `generic-interface` warning that the UI surfaces. A caller-supplied descriptor for the same `(chainId, to, selector)` always wins. Callers can pass `builtins: false`. Alternative: keep generic knowledge in wallet-web as today. Rejected because BYO origins would lose it and R1's "library usable by every service" argues for one place.

### D4 — `describeTransaction` is a runtime method in wallet-kit
`WalletRuntime` gains `describeTransaction(tx: TransactionRequest): Promise<TransactionDescription>`. Implementation in `packages/wallet-kit/src/describe.ts`: fetch `GET {walletApiUrl}/v1/tx-mappings?chainId=` (3 s timeout, cached per runtime for 60 s, stale value kept on failure), merge with built-ins, resolve tokens via the runtime's `publicClient` (`symbol()` and `decimals()` multicall-free reads, 3 s timeout, per-address in-memory cache), native currency from the chain descriptor. Never rejects. Alternative: wallet-web fetches and describes itself. Rejected: it violates WK-30 and BYO origins would each reimplement it.

### D5 — Native currency comes from the chain descriptor
`WalletChainConfig` (and the shared zod descriptor in `packages/contracts/chains.ts`) gains an optional `nativeCurrency: { symbol, decimals }`, defaulting to `{ ETH, 18 }`. `buildRuntime` already calls `defineChain` with a hard-coded ETH; it reads the descriptor instead. The wallet-web config templates pass it through when set. Alternative: viem's chain registry by id. Rejected: private and custom chains (the devnet is 31337) are first-class in Giano.

### D6 — Storage mirrors sponsorship rules: one row per key, full-replace, history by key hash
Migration `0006_tx_mappings.sql` adds `tenant_tx_mappings (id uuid, tenant_id, chain_id bigint, contract text, descriptor jsonb, updated_at, updated_by_key_hash, UNIQUE (tenant_id, chain_id, contract))` and `tenant_tx_mappings_history (id, tenant_id, chain_id, contract, action text CHECK IN ('put','delete'), descriptor jsonb NULL, created_at, created_by_key_hash)` with an index on `(tenant_id, chain_id, created_at DESC)`. Writes and history go in one transaction as `writeConfig` does in `routes/admin-sponsorship.ts`. Descriptors are validated with the library's validator on write and again on read for serving (the sponsorship rules do the same and for the same reason: never interpret a row the current code does not trust). Body limit 64 KiB on the PUT route. Alternative: a single jsonb array per `(tenant, chain)` like `tenant_sponsorship.config`. Rejected: per-contract rows give natural PUT/DELETE semantics and history granularity, and a tenant with many contracts should not resend all of them to change one.

### D7 — The wallet-facing read is tenant-by-Origin-or-Host, no session, per chain
`GET /v1/tx-mappings?chainId=` resolves the tenant from Origin when present and from Host otherwise, then `requireChain`. The Host fallback is not optional: the stock wallet calls `/api/v1/tx-mappings` same-origin through its nginx, and browsers send no Origin header on a same-origin GET, so an Origin-only rule would make every stock-wallet read a 403 (found in the first e2e run). nginx already forwards `Host` for exactly this reason: `/.well-known/webauthn` resolves by Host too. The mapping set is public within the tenant, and the review screen must not wait on session restore (WK-12 restores it silently in parallel). Response carries `Cache-Control: private, max-age=60` to match the kit's cache. Alternative: `requireSession`. Rejected as stated; it also adds nothing, since a session proves the user, not the tenant. Alternative: a POST so the browser sends Origin. Rejected: a read with POST semantics to work around a header is worse than using the header the proxy already forwards.

### D8 — Approval waits for the description as well as the pre-flight
The review screen renders the approve control only when both promises have settled. The description path is bounded (D4 timeouts) so this adds at most a few seconds in the worst case and nothing in the common one, and it is the whole point: a user must have seen the summary, or the warning that there is none, before the button exists. This is the same reasoning the pre-flight gate already applies.

### D9 — Surfacing in wallet-web
`ReviewTransaction.tsx` calls `runtime.describeTransaction(tx)` alongside `checkSponsorship`. Rendering order: origin banner, network, intent (`data-testid="tx-intent"`), fields (`data-testid="tx-field"`), native value when non-zero, generic-interface note (`data-testid="tx-generic-note"`), technical details `<details>` (contract, signature, calldata). Unknown: warning card (`data-testid="tx-unknown"`, `data-reason`), selector and contract, raw calldata (`data-testid="tx-raw"`). The two-ABI decode and the direct `@appliedblockchain/giano-contracts` import are removed from wallet-web. Styles stay within the existing `.card`, `.kv`, `.data-box` vocabulary; one new class for the warning card.

### D10 — The e2e suite exercises the tenant path, not only the generic one
The Playwright suite publishes a descriptor for the demo ERC-20 through the admin API in test setup (the sponsorship suite already drives admin routes this way), so the stock-wallet assertion covers a tenant-sourced description, and the BYO assertion runs against the generic fallback by using a contract with no tenant mapping. Alternative: seed through `TENANTS_SEED`. Rejected: mappings are admin-key data, and the seed is deliberately declarative tenant identity only (the sponsorship tables make the same split).

### D11 — Package plumbing
`packages/tx-describe` copies `packages/wallet-transport`'s tsup, tsconfig and package.json layout (ESM+CJS, `sideEffects: false`, GitHub Packages, `publishConfig.access: restricted`). Added to the changesets `fixed` group so it versions with its siblings, to `ci.yml`'s package build/test steps, and referenced from wallet-kit and wallet-api as `workspace:^`. A changeset accompanies the change (minor for the kit's new runtime method and chain field, minor for the new package).

## Risks / Trade-offs

- [Pre-1.0 engine changes its API or output] → adapter boundary (D2); exact pin; library tests snapshot the built-ins' output so an upgrade that changes wording is visible; in-house fallback path defined.
- [A tenant publishes a misleading descriptor] → a tenant can only bind descriptors to contracts it chooses, and the description names the contract; this is the same trust the user already extends to the tenant's dApp. Generic and unknown results are visibly flagged so a tenant cannot make an unmapped call look explained.
- [Descriptor authoring is harder than the allowlist] → docs ship a complete worked example for an ERC-20 and point at the public registry; validation returns per-path issues; the admin list flags stale rows.
- [Token reads add latency to the review] → bounded timeouts, per-address cache, and the read runs concurrently with the pre-flight; failure degrades to an unscaled amount with a warning, never blocks.
- [Bundle growth in wallet-web] → the engine's only runtime dependency is `@noble/hashes`, already present via viem; measured in the spike.
- [Serving descriptors without a session] → they contain no secrets and are scoped to the tenant by Origin; a probe with an unregistered Origin learns nothing (403).

## Migration Plan

1. Merge and release the library, kit and API together (one changeset set). The API migration is additive.
2. Deploy wallet-api first. Until wallet-web is redeployed nothing calls the new routes.
3. Deploy wallet-web. Before any tenant publishes mappings, users see built-in generic descriptions for standard token calls and explicit unknowns elsewhere, which is already strictly more honest than today.
4. Tenants publish descriptors through the admin API; effect is immediate on the next review (60 s cache at most).

Rollback: redeploy the previous wallet-web image; the API routes and tables are inert when unused. Dropping the tables is a manual follow-up migration if ever needed.

## Open Questions

- Cache TTL (60 s) and timeouts (3 s) are starting values; tune from e2e and dev-stack timings during implementation without spec change.
