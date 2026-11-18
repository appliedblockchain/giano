# Design

## Context

See `proposal.md` for the motivation. The current state that shapes the approach:

- 33 source files import `zod`. 25 are in `services/wallet-api`. The rest are in `contracts`, `tx-describe`, `wallet-transport`, `bundler` and `custom-example`. All of them import from `"zod"`.
- `wallet-api` uses `fastify-type-provider-zod` 4.0.2 for request validation (`validatorCompiler`), response serialization (`serializerCompiler`) and OpenAPI generation (`jsonSchemaTransform`, in `src/app.ts`). Its error handler (`src/plugins/error-handler.ts`) turns validation errors into `400 { error: "validation", issues: [{ path, message }] }`. It reads `instancePath` and `message` from each validation error.
- `wallet-transport` (`src/protocol.ts`) and `contracts` (`chains.ts`) write out the type of every exported schema. A comment in `protocol.ts` says why: so that each type can be read without inference (`isolatedDeclarations`). These annotations use zod 3 generics, such as `z.ZodObject<Shape, "strip">`.
- The code already reads `error.issues`, not the `error.errors` alias that zod 4 removes.
- Every `@appliedblockchain/*` package is in one changesets `fixed` group, so all of them always share one version.
- The root lockfile has three zod 3 copies, all affected by GHSA-mrhx-c7xc-m3w5: 3.24.4 (our packages), 3.25.1 (a direct dependency of `@wagmi/cli` 2.3.1 in `contracts`) and 3.22.4 (a direct dependency of `@reown/appkit-wallet` 1.7.8). `abitype`, and through it `viem` and `ox`, takes zod as an optional peer and resolves whichever copy is nearest. `abitype@1.0.8` accepts only zod 3 as that peer (see D9). That is why `pnpm audit` reports 213 paths.
- The `custom-example` lockfile has the same 3.22.4 and 3.25.1 copies, plus 3.24.4 from the published Giano 5.0.0 packages.
- ABIP-6 (7-day minimum release age) and ABIP-7 (exact versions) apply to every version chosen here.

## Goals / Non-Goals

**Goals:**

- The root lockfile contains no zod version below 4.6.6, and `pnpm audit` no longer reports GHSA-mrhx-c7xc-m3w5 there.
- Every workspace package resolves `zod` 4.6.7 and passes its CI gates without behaviour changes that a spec describes.
- The `400` validation body keeps its shape, and the OpenAPI document keeps its meaning.
- The PR stays reviewable: each commit has one purpose, and code changes are only those that zod 4 forces.

**Non-Goals:**

- Migrating APIs that zod 4 only deprecated. That can be a later change.
- Moving `zod` from `dependencies` to `peerDependencies` in the published packages.
- Changing error message texts back to the zod 3 wording.
- Updating `custom-example` to the new Giano release. That happens after publishing, as in #174.

## Decisions

### D1. Target zod 4.6.7 and `fastify-type-provider-zod` 7.0.0

zod 4.6.7 (released 2026-10-12) is the latest 4.x and is past the 7-day release age. `fastify-type-provider-zod` 7.0.0 (2026-06-24) is the latest release and needs `zod >= 4.1.5`, `fastify ^5.5.0` (we have 5.12.7) and `@fastify/swagger >= 9.5.1` (we have 9.8.1).

Version 7 serializes responses with zod's `safeEncode`, against `z.output` of the schema. Version 6 used `safeParse` against `z.input`. `safeEncode` fails on a one-way `.transform()`. All `wallet-api` response schemas are plain objects. The schemas that use `.transform()` (`sponsorshipConfigSchema`, `tenantFieldsSchema` and the schemas derived from it, `platformAdminInputSchema`) are used only as request bodies or with a direct `safeParse`. Version 7 is therefore safe.

*Alternative considered:* 6.1.0, which keeps parse-based serialization. Rejected: it is a year old, its release line is closed, and we would face the version 7 move later anyway.

### D2. Import from `"zod"`, with no bridge release

With zod 4, the package root `"zod"` exports the zod 4 API. Imports stay as they are.

*Alternative considered:* first move to zod 3.25 and import `"zod/v4"`, then migrate file by file. Rejected: the code base is small (33 files). A bridge would leave two APIs side by side and need a second import rewrite at the end.

### D3. Migrate only what zod 4 removes or changes

| zod 3 usage | Where | zod 4 form |
|---|---|---|
| `invalid_type_error`, `required_error` | `tx-describe/src/validate.ts` (2), `bundler/src/config.ts` (3) | `error: (issue) => (issue.input === undefined ? <required text> : <type text>)`, keeping today's custom texts |
| `z.record(value)` | `tx-describe/src/validate.ts` (4), `wallet-api` (10, in `platform-tenants.ts`, `admin-sponsorship.ts`, `webauthn.ts`, `wallet-management.ts`, `services/tenants.ts`) | `z.record(z.string(), value)` |
| zod 3 generics in explicit annotations | `wallet-transport/src/protocol.ts`, `contracts/chains.ts` | see D4 |
| any other type error the compiler reports | found by `typecheck` | the zod 4 equivalent |

Deprecated APIs stay: `message:`, `.passthrough()`, `.strict()`, `z.string().url()`, `.uuid()`, `.datetime()`, `z.ZodIssueCode.custom` and `fatal: true` in `addIssue`. If one of them no longer type-checks, migrate that one only (for example, `fatal: true` → `continue: false`).

`.uuid()` becomes stricter: zod 4 requires the RFC 9562 variant bits. We keep it. The `wallet-api` database generates ids with `gen_random_uuid()` (`defaultRandom()` in `src/db/schema.ts`), and those comply. The only non-compliant UUIDs in the repository are two literals in `test/sponsorship-signer.test.ts`. They go through `tenantIdToBytes16`, not through a zod schema.

*Alternative considered:* migrate every deprecated API at the same time. Rejected: about 180 extra edits (137 `message:` alone) would hide the changes that matter.

### D4. Rewrite the explicit annotations with zod 4 generics

The packages keep their explicit types (the `isolatedDeclarations` convention). Only the generics change:

- `z.ZodObject<Shape, "strip">` → `z.ZodObject<Shape, z.core.$strip>`, and `"strict"` → `z.core.$strict`.
- `z.ZodEnum<["a", "b"]>` → `z.ZodEnum<{ a: "a"; b: "b" }>`, because zod 4 types an enum as an object.
- `z.ZodDiscriminatedUnion<"type", [...]>` → the zod 4 parameter list. Confirm it against `node_modules/zod` during implementation.
- `z.ZodType<T>`, `z.ZodOptional`, `z.ZodLiteral`, `z.ZodDefault`, `z.ZodArray`, `z.ZodString` and `z.ZodNumber` keep their names.

The emitted `.d.ts` files (`pnpm -F <package> build`) are the check: they must contain no `any` that was not there before.

### D5. Keep the `400` contract without changing the error handler

`fastify-type-provider-zod` 7.0.0 still builds each validation error with `instancePath` (`/` followed by `path.join("/")`) and `message` (`createValidationError` in its `src/errors.ts`). `hasZodFastifySchemaValidationErrors` still exists. `error-handler.ts` therefore stays unchanged. The `wallet-api` tests for `400` responses confirm that the body still has one issue per violation, with a path and a message (`tenant-administration` spec).

The default message texts change in zod 4. Example: `Expected string, received number` becomes `Invalid input: expected string, received number`. No spec fixes the text. The one test that matches a zod text, `test/tenants.test.ts:134` (`/Unrecognized key/`), still matches zod 4's `Unrecognized key: "…"`.

### D6. Regenerate the OpenAPI document, then review its meaning

`fastify-type-provider-zod` 7 builds JSON Schema with zod's `z.toJSONSchema` instead of `zod-to-json-schema`. The document's text will change. One example: `"nullable": true` (49 occurrences today) becomes an `anyOf` that includes `{ "type": "null" }`, which is the OpenAPI 3.1 form. The document already declares `"openapi": "3.1.0"`. Run `pnpm -F @appliedblockchain/giano-wallet-api openapi`, then review the diff for changes in meaning: required fields, types, enums, formats, and request or response shapes. Change `zodToJsonConfig` only if the review finds a change in meaning.

### D7. Record the release as a major version

Add one major changeset for `giano-wallet-transport` and `giano-contracts`, whose exported types change. Add a patch changeset for `giano-tx-describe`, whose public types do not include zod. The changeset text also names GHSA-mrhx-c7xc-m3w5: the published packages depend on `zod` directly, so consumers get the fix by installing 6.0.0. Because of the `fixed` group, every published package moves to 6.0.0. `wallet-api` and `bundler` are in the changesets `ignore` list and need no changeset.

*Alternative considered:* a minor version, because the runtime behaviour of `.parse()` does not change. Rejected: the declared types of exported values change, which breaks a consumer that composes them with zod 3 or names their types.

### D8. Commit order

The repository's rules require that a lockfile change is committed alone, with the manifest change that caused it. The PR commits are:

1. the OpenSpec change;
2. the root manifests (including `@wagmi/cli`), `pnpm-workspace.yaml` and `pnpm-lock.yaml`;
3. the `custom-example` manifest, its `pnpm-workspace.yaml` and its own `pnpm-lock.yaml`;
4. code migration, one commit per package;
5. the regenerated `openapi.json`, and `generated.ts` if it changed;
6. the changesets.

Commits 2 and 3 do not type-check by themselves. Reviewers read the PR as a whole, and CI runs on its head.

### D9. Remove every vulnerable zod copy, not only our own

GHSA-mrhx-c7xc-m3w5 has no zod 3 fix, so each zod 3 copy must go:

- **`zod@3.25.1` (`@wagmi/cli`):** upgrade `@wagmi/cli` in `packages/contracts` from 2.3.1 to 2.10.0 (2026-02-16, past the release age). From 2.6.0 it depends on `zod ^4.1.11`. Its only peer is `typescript >= 5.7.3` (we have 7.0.2). It runs only at build time (`gen:abis`), and CI checks its output with `git diff --exit-code packages/contracts/generated.ts`.
- **`zod@3.22.4` (`@reown/appkit-wallet`):** add the override `"@reown/appkit-wallet>zod": "4.6.7"` to both `pnpm-workspace.yaml` files, with the advisory in a comment, as the existing security overrides do. Every release up to the latest (1.8.24) pins 3.22.4, so no upgrade path exists. Its `W3mFrameSchema` uses only `z.object`, `z.string`, `z.literal`, `z.array`, `z.any`, `z.enum`, `z.number`, `z.boolean`, `.or`, `.extend`, `.optional`, `.nullable`, `.email` and two-argument `z.record`, and it calls `.parse`. All of these behave the same in zod 4, with one exception found during implementation: zod 4 rejects an object whose `z.any()` key is absent, and zod 3 accepted it. This affects only `params` of the `wallet_getAssets` and `wallet_revokePermissions` RPC requests. No installed caller omits `params` (`viem` always sends it), and Giano does not use the AppKit embedded wallet, so the override stays. Its zod 3 type declarations are not checked (`skipLibCheck: true` in `tsconfig.base.json` and in `custom-example`).
- **`zod@3.25.1` (`abitype@1.0.8`):** found during implementation. `viem@2.23.2`, reached through `@walletconnect/utils` 2.21.x (wagmi → `@wagmi/connectors` → WalletConnect), pins `abitype` to exactly `1.0.8`. That version's optional `zod` peer accepts only `^3 >=3.22.0`, so pnpm keeps a zod 3 copy for it even after `@wagmi/cli` moves to zod 4. Add the override `"abitype@1.0.8": "1.2.3"` to both `pnpm-workspace.yaml` files, with the advisory in a comment. `1.2.3` is a semver-compatible minor release, the rest of the tree already uses it, and its `zod` peer accepts `^4.0.0`. `viem` uses `abitype` for ABI types and parsing only, not its `abitype/zod` entry point.
  *Alternative considered:* upgrade `@wagmi/connectors` and WalletConnect until no parent pins `abitype@1.0.8`. Rejected: a much larger change with more runtime risk.
- **`zod@3.24.4` in `custom-example` (from published Giano 5.0.0):** this copy cannot go until 6.0.0 is published. Record it as an accepted residual in the PR description, as the `dependency-security` spec requires: package, severity, advisory, the workspace it reaches (`custom-example`), the reason (fixed only by a Giano release that this PR produces), and the follow-up (the PR that installs 6.0.0).

*Alternative considered for `appkit-wallet`:* record it as an accepted residual instead of overriding it, because the frame validates messages from WalletConnect's own origin. Rejected: the override has a small, checkable risk, and it closes a high advisory on 200 or more paths. A residual would stay open with no upstream end date.

## Risks / Trade-offs

- [`.default()` changes meaning: zod 4 returns the default without parsing it, and the default must have the output type] → `typecheck` reports defaults of the wrong type. Then look at each `.default()` combined with `z.coerce` or `.transform()` in the `config.ts` files of `wallet-api`, `bundler` and `custom-example`. Use `.prefault()` where the old behaviour is needed. The config tests confirm the parsed values.
- [`z.number()` rejects `Infinity`, and `.int()` accepts only safe integers] → no current value is affected (chain ids and gas limits are small or are strings). The tests cover config parsing.
- [`openapi-types` is a new peer dependency of `fastify-type-provider-zod` 7] → pnpm installs peers automatically. If `wallet-api typecheck` needs it directly, add it as an exact `devDependency` in the same manifest and lockfile commit.
- [`@reown/appkit-wallet` misbehaves on zod 4 at runtime] → a smoke test parses sample frame and app events with its `W3mFrameSchema` under zod 4 (task 4.6), and the connector builds. The end-to-end suite does not use WalletConnect, so the smoke test is the main check. If the smoke test fails, remove the override and record a residual instead (D9 alternative).
- [`@wagmi/cli` 2.10.0 writes `generated.ts` differently] → run `gen:abis`, then review the diff. Changes in form are accepted. A change in an ABI is a defect and stops the upgrade of `@wagmi/cli`.
- [A consumer of the published packages breaks] → the major version and the changeset text tell consumers to move to zod 4.
- [The OpenAPI document changes] → see D6. Integrators who generate clients from the document regenerate them once.

## Migration Plan

There is no data or schema migration. `wallet-api` and `bundler` deploy through the normal pipeline. To roll back, revert the PR: no stored data depends on the zod version. The published packages ship through the changesets release flow as 6.0.0. A follow-up PR updates `services/custom-example` to 6.0.0.

## Open Questions

- Should a later change migrate the deprecated APIs listed in D3? Nothing in this change depends on the answer.
