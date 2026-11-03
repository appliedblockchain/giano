# Tasks

## 1. Baseline

- [x] 1.1 On the unmodified branch, run `pnpm install --frozen-lockfile`, `pnpm typecheck`, `pnpm exec biome ci .`, and the `test` script of `giano-contracts`, `giano-tx-describe`, `giano-wallet-transport`, `giano-bundler` and `giano-wallet-api`, plus `pnpm -F @appliedblockchain/giano-wallet-api openapi:check`. Record any failure that exists before the upgrade, so no later step is blamed for it. Done when the results are saved in the scratchpad.
- [x] 1.2 Save `pnpm audit --json`, in the root and in `services/custom-example`, to the scratchpad. Done when both files exist, and the root one lists GHSA-mrhx-c7xc-m3w5 (213 paths at planning time).

## 2. Dependencies (one manifest and lockfile commit per workspace)

- [x] 2.1 Set `zod` to exactly `4.6.7` in `packages/contracts`, `packages/tx-describe`, `packages/wallet-transport`, `services/bundler` and `services/wallet-api`. Set `fastify-type-provider-zod` to exactly `7.0.0` in `services/wallet-api` (design D1). Set `@wagmi/cli` to exactly `2.10.0` in `packages/contracts` (design D9). Verify that `node scripts/check-pinned-versions.mjs` passes.
- [x] 2.2 In the root `pnpm-workspace.yaml`, remove the `zod-to-json-schema` override. Add `"@reown/appkit-wallet>zod": "4.6.7"`, with a comment naming GHSA-mrhx-c7xc-m3w5 and saying that no `appkit-wallet` release moves to zod 4 (design D9). Add `"abitype@1.0.8": "1.2.3"`, with a comment naming the advisory and the `viem@2.23.2` pin (design D9). Run `pnpm install`. Verify that `pnpm-lock.yaml` has no zod version below 4.6.6 and no `zod-to-json-schema` entry, and that `pnpm audit` no longer reports GHSA-mrhx-c7xc-m3w5.
- [x] 2.3 Verify that `node scripts/check-release-age.mjs --registry` passes and that `pnpm install --frozen-lockfile` leaves the lockfile unchanged.
- [x] 2.4 In `services/custom-example`: set `zod` to exactly `4.6.7`, and add the same `appkit-wallet` and `abitype` overrides to its `pnpm-workspace.yaml` (the `abitype` one only if its lockfile has `abitype@1.0.8`). Remove its `zod-to-json-schema` override if the lockfile no longer needs that package. Run `pnpm install` there. Verify that `pnpm audit` there reports GHSA-mrhx-c7xc-m3w5 only on paths through the published Giano 5.0.0 packages (`zod@3.24.4`), and that `pnpm install --frozen-lockfile` leaves its lockfile unchanged.

## 3. Published packages

- [x] 3.1 `packages/contracts/chains.ts`: rewrite the explicit zod annotations with zod 4 generics (design D4). Verify that `pnpm -F @appliedblockchain/giano-contracts typecheck`, `build:ts` and `test:deploy` pass, and that the emitted `.d.ts` types the schemas with no new `any`.
- [x] 3.2 `packages/contracts`: run `pnpm gen:abis` with `@wagmi/cli` 2.10.0 and review the diff of `generated.ts`. Accept changes in form. Stop and report any change to an ABI (design D9 risk). Done when `git diff --exit-code packages/contracts/generated.ts` passes after a second `gen:abis` run on the committed result.
- [x] 3.3 `packages/tx-describe/src/validate.ts`: replace `invalid_type_error` with the `error` function, keeping the custom texts, and give each `z.record` a `z.string()` key (design D3). Verify that `pnpm -F @appliedblockchain/giano-tx-describe typecheck`, `test` and `build` pass, and that the existing tests still see the custom messages.
- [x] 3.4 `packages/wallet-transport/src/protocol.ts`: rewrite the explicit annotations (`ZodObject` with `z.core.$strip`, `ZodEnum` as an object type, `ZodDiscriminatedUnion` with the zod 4 parameters; design D4). Verify that `pnpm -F @appliedblockchain/giano-wallet-transport typecheck`, `test` and `build` pass, and that the emitted `.d.ts` has no new `any`.

## 4. Services and connector

- [x] 4.1 `services/bundler/src/config.ts`: replace `invalid_type_error` and `required_error` with the `error` function, keeping the texts (design D3). Check each `.default()` used with `z.coerce` or `.transform()`, and use `.prefault()` where the old behaviour is needed. Verify that `pnpm -F @appliedblockchain/giano-bundler typecheck` and `test` pass.
- [x] 4.2 `services/wallet-api`: give the 10 single-argument `z.record` calls a `z.string()` key, and fix every other error that `typecheck` reports with its zod 4 equivalent. Migrate a deprecated API only if it no longer type-checks (design D3). Check each `.default()` in `src/config.ts` used with `z.coerce` or `.transform()`. Verify that `pnpm -F @appliedblockchain/giano-wallet-api typecheck` passes.
- [x] 4.3 `services/wallet-api`: run the test suite. Confirm that the `400` validation tests still return one issue per violation, each with `path` and `message` (design D5, `tenant-administration` spec). Confirm that the routes with response schemas still serialize under the encode-based serializer (design D1). Verify that `pnpm -F @appliedblockchain/giano-wallet-api test` passes. Update a test only where it asserts a zod default message text.
- [x] 4.4 `services/wallet-api`: run `pnpm -F @appliedblockchain/giano-wallet-api openapi` and review the diff of `openapi/openapi.json`. Accept changes in form, such as `nullable` becoming an `anyOf` with `null`. Investigate any change in meaning (required fields, types, enums, formats, shapes) and fix it through `zodToJsonConfig` or the schema (design D6). Verify that `openapi:check` passes, and record a short summary of the reviewed diff for the PR description.
- [x] 4.5 `services/custom-example/src/config.ts`: fix any error that zod 4 causes. Verify that `pnpm typecheck` and `pnpm build` pass in `services/custom-example`.
- [x] 4.6 Smoke-test `@reown/appkit-wallet` on zod 4 (design D9). Write a throwaway script in the scratchpad that imports its `W3mFrameSchema` from the connector's dependency tree. The script parses one valid and one invalid sample of `frameEvent` and `appEvent`. Verify that the valid samples parse, the invalid ones throw, and `pnpm -F @appliedblockchain/giano-connector build` passes. If the smoke test fails, remove the override and record a residual instead.

## 5. Release notes

- [x] 5.1 Run `pnpm changeset`. Add a **major** changeset for `@appliedblockchain/giano-wallet-transport` and `@appliedblockchain/giano-contracts`, and a patch changeset for `@appliedblockchain/giano-tx-describe` (design D7). The text says that exported schemas are now zod 4 types, that consumers must use zod 4 to compose them, and that the release fixes GHSA-mrhx-c7xc-m3w5. Verify that `pnpm release:status` shows every package of the `fixed` group moving to 6.0.0.

## 6. Integration checks

- [x] 6.1 Run the full set of CI gates from the repository root: `pnpm typecheck`, `pnpm exec biome ci .`, `node scripts/check-pinned-versions.mjs`, `node scripts/check-release-age.mjs --registry`, and the `build` of `giano-wallet-core`, `giano-wallet-kit`, `giano-connector`, `giano-paymaster-sdk` and `giano-paymaster-admin`. These packages consume `wallet-transport` and `contracts` through `workspace:`. Compare with the baseline from 1.1. Done when no new failure appears.
- [x] 6.2 Run the end-to-end suite (`deploy/docker-compose.e2e.yml` and Playwright, as in `.github/workflows/e2e.yml`). Verify that it passes on the final tree.
- [x] 6.3 Compare `pnpm audit` in the root and in `custom-example` with the baseline from 1.2. Verify that GHSA-mrhx-c7xc-m3w5 is gone from the root, and that no new advisory appears in either workspace. Write the accepted-residual entry for `custom-example`'s `zod@3.24.4` (package, severity, advisory, workspace, reason, follow-up) for the PR description (`dependency-security` spec).
- [x] 6.4 Run `openspec validate upgrade-zod-v4 --strict` and verify that it passes.

## Workflow follow-up

- Open the PR `fix(deps): upgrade zod to v4 for GHSA-mrhx-c7xc-m3w5` with the commit order from design D8. Add the ticket code if one exists. Put the OpenAPI review summary (4.4) and the residual entry (6.3) in the description.
- After the merge and the 6.0.0 release, update `services/custom-example` to the published 6.0.0 packages in a separate PR. That PR removes the last `zod@3.24.4` and closes the residual.
- Archive the change with `/opsx:archive` once the PR is merged.
