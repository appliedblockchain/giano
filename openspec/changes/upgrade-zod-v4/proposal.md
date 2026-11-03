# Proposal

## Why

Every zod version below 4.6.6 has a high-severity advisory: GHSA-mrhx-c7xc-m3w5 (CVE-2023-54404, "Zod can exhaust memory while validating oversized constrained collections"). No zod 3 release fixes it. `pnpm audit` reports it on 213 paths. Three zod 3 copies are in the tree: our own 3.24.4, 3.25.1 from `@wagmi/cli`, and 3.22.4 from `@reown/appkit-wallet`. The `dependency-security` spec allows no unaddressed high advisory, so moving to zod 4 is the only fix.

Zod 3 is also in maintenance mode. Libraries we depend on are moving to zod 4: `fastify-type-provider-zod` has supported only zod 4 since 6.0. Staying on zod 3 keeps `fastify-type-provider-zod` on 4.0.2 (October 2024) and keeps the `zod-to-json-schema` override in `pnpm-workspace.yaml`.

## What Changes

- Upgrade `zod` from 3.24.4 to 4.6.7 in `packages/contracts`, `packages/tx-describe`, `packages/wallet-transport`, `services/wallet-api` and `services/bundler`. Upgrade it from 3.25.1 to 4.6.7 in `services/custom-example`, which has its own workspace and lockfile.
- Upgrade `fastify-type-provider-zod` from 4.0.2 to 7.0.0 in `services/wallet-api`, in the same step as zod, because 4.0.2 accepts only zod 3.
- Remove the `zod-to-json-schema` override from `pnpm-workspace.yaml`. Only `fastify-type-provider-zod` 4.0.2 needs that package.
- Upgrade `@wagmi/cli` from 2.3.1 to 2.10.0 in `packages/contracts` (a dev dependency for ABI generation). From 2.6.0, it depends on zod 4, which removes the `zod@3.25.1` copy.
- Override `zod` to 4.6.7 under `@reown/appkit-wallet`, in both workspaces. Even its latest release (1.8.24) pins `zod` 3.22.4, so no upstream fix exists. It uses only zod APIs that work the same in zod 4.
- Override `abitype@1.0.8` to 1.2.3, in both workspaces. `viem@2.23.2` (through WalletConnect) pins `abitype@1.0.8`, whose optional zod peer accepts only zod 3, so it keeps a `zod@3.25.1` copy. `abitype@1.2.3` accepts zod 4.
- In `services/custom-example`, the published Giano 5.0.0 packages still bring `zod@3.24.4`. Only the Giano 6.0.0 release removes that copy. Until the follow-up PR installs 6.0.0, it stays as a documented accepted residual.
- Migrate the APIs that zod 4 removed or changed:
  - `invalid_type_error` and `required_error`, which zod 4 dropped, in `tx-describe` and `bundler`.
  - Single-argument `z.record(value)`, which zod 4 dropped, in `tx-describe` and `wallet-api`.
  - The explicit zod type annotations in `wallet-transport` and `contracts`. These packages write them out for `isolatedDeclarations`, and zod 4 changed the generics.
- Leave APIs that zod 4 only deprecated (`message:`, `.passthrough()`, `.strict()`, `z.string().url()`, `z.ZodIssueCode.custom`, `fatal: true`) as they are. They still work, and keeping them keeps the diff reviewable.
- Regenerate the committed OpenAPI document of `wallet-api`. The JSON Schema generator changes from `zod-to-json-schema` to zod's own `z.toJSONSchema`, so the document's text changes. Its meaning must not change.
- **BREAKING** (TypeScript API of the published packages): `@appliedblockchain/giano-wallet-transport` and `@appliedblockchain/giano-contracts` export zod schemas. Their declared types become zod 4 types. A consumer that composes these schemas with its own zod 3 schemas, or names their types, must move to zod 4. A major changeset records this. The changesets `fixed` group then moves every published Giano package to the next major version.

No runtime behaviour that a spec describes changes, so the change declares `skip_specs: true`. Three contracts in the current specs must still hold after the upgrade, and tasks verify each:

- `dependency-security`: no unaddressed high advisory, and every advisory left open is documented with a reason. This change fixes GHSA-mrhx-c7xc-m3w5 in the root workspace and records the one residual path in `custom-example`.
- `tenant-administration`: a validation failure returns `400` with one issue per violation, each with a field path and a message.
- `tenant-transaction-mappings`: the committed OpenAPI document reflects the routes, and the drift check passes.

The default text of zod's error messages changes in zod 4. No spec fixes that text.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

None. This is a dependency upgrade with no change to spec-level behaviour (`skip_specs: true`).

## Impact

- **Manifests and lockfiles:** six `package.json` files, both `pnpm-workspace.yaml` files (root and `custom-example`), `pnpm-lock.yaml` and `services/custom-example/pnpm-lock.yaml`.
- **Code:** `packages/wallet-transport/src/protocol.ts`, `packages/contracts/chains.ts`, `packages/tx-describe/src/validate.ts`, `services/bundler/src/config.ts`, and the `wallet-api` files that use single-argument `z.record`. Type errors may appear in more `wallet-api` files.
- **Generated files:** `services/wallet-api/openapi/openapi.json`, and possibly `packages/contracts/generated.ts` if `@wagmi/cli` 2.10.0 writes it differently.
- **Releases:** a major changeset for `giano-wallet-transport` and `giano-contracts`, and a patch changeset for `giano-tx-describe`. Through the `fixed` group, all seven published packages move to the next major version. `services/custom-example` picks up that release in a later PR, as it did for 5.0.0 (#174).
- **Transitive users of zod:** `viem` and `ox` reach zod only through `abitype`, which takes it as an optional peer. `abitype@1.2.3` accepts zod 4 (`^3.22.0 || ^4.0.0`); `abitype@1.0.8` does not, so it is overridden to 1.2.3. Once no zod 3 copy is left, `abitype` resolves zod to 4.6.7.
- **Connector runtime:** `@reown/appkit-wallet` (WalletConnect's embedded wallet frame, reached through RainbowKit → wagmi → `@wagmi/connectors`) runs on zod 4 because of the override.
