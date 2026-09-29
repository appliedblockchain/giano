## 1. Kick-off (command preamble)

- [ ] 1.1 Run `/ae-dependency-vulnerability-fix` on branch `chore/dependency-vulnerability-fix` from a cleared context; answer its Jira prompt with "skip" (no Jira for this project) so the report records it
- [ ] 1.2 Confirm the detected gates against design D4 and add the ones it misses (`wallet-api openapi:check`, ABI drift via `hh:compile` + `hh:wagmi`, `forge test`, determinism recompute, Playwright e2e)
- [ ] 1.3 Confirm the package manager (pnpm 11.15.1) and the workspace map (12 packages; submodule lockfiles excluded)
- [ ] 1.4 Record the cooldown finding: `minimumReleaseAge: 1440`, existing excludes `baseline-browser-mapping`, `postcss`

## 2. Baseline

- [ ] 2.1 Save the baseline `pnpm audit --json` and the open Dependabot alerts (severity, package, manifest) to the scratchpad for the final diff
- [ ] 2.2 Run every gate from D4 on the unmodified branch; record any pre-existing failure so it is not blamed on a bump
- [ ] 2.3 For each advisory, work out its fix path (direct bump, parent bump, or scoped override) and assign each package to the lowest severity level it appears at (D3)

## 3. Low severity

- [ ] 3.1 Fix low-only packages (`cookie`, `tmp`, `elliptic`, `diff`, `qs`, low `brace-expansion`), plus the multi-level packages whose lowest level is low (`handlebars`, `axios`, `undici`), each bumped to a version clearing all its advisories
- [ ] 3.2 `pnpm install`; handle any cooldown block per package (wait or exclude by name, noted for the report)
- [ ] 3.3 Run the per-level gates; fix regressions before moving on

## 4. Moderate severity — including the OpenZeppelin re-freeze

- [ ] 4.1 Fix the remaining moderate packages: `uuid` in wallet-core, `fastify` in wallet-api, `vitest` → ≥4.1.11 across the six vitest packages (with `@vitest/mocker`), plus transitive `js-yaml`, `bn.js`, `ajv`, `yaml`, `lodash`, `follow-redirects`, `serialize-javascript`, `ws`, `postcss`, `decode-uri-component`, `@metamask/sdk*`, `@protobufjs/utf8`, `h3`, `picomatch`, `protobufjs`
- [ ] 4.2 Adapt test config and test code to vitest 4 where the gates require it
- [ ] 4.3 Bump `@openzeppelin/contracts` and `@openzeppelin/contracts-upgradeable` together to the same ≥5.4.0 version (upgradeable stays pinned exactly)
- [ ] 4.4 Recompile (`hh:compile`), regenerate ABIs (`hh:wagmi`), and run `forge test`
- [ ] 4.5 On a fresh anvil, run the determinism workflow's deploy sequence; capture the new paymaster trio and test ERC-20 addresses, and confirm factory and implementation are unchanged
- [ ] 4.6 Write the new values into `canonical.ts` (and update its freeze comment) and `addresses.ts`; regenerate `e2e/devnet/addresses.json` / `state.json` via `generate-state.mjs`
- [ ] 4.7 `git grep` the old addresses and replace them in compose files, `infra/iac/ecs_services.vars.tf`, paymaster-admin `public/config.json`, `docs/E2E-DEV-KEYS.md` and the paymaster-sdk test fixture; commit the re-freeze as one commit
- [ ] 4.8 `pnpm install`; run the per-level gates plus the determinism recompute; fix regressions before moving on

## 5. High severity

- [ ] 5.1 Fix the high packages: `drizzle-orm` → ≥0.45.2 in wallet-api, plus transitive `glob`, `minimatch`, `brace-expansion`, `preact`, `socket.io-parser`, `defu`, `immutable`, `@grpc/grpc-js`, `form-data`, `adm-zip`, `fast-uri`, `find-my-way`, `@fastify/static`, `nanoid`, `browserslist`, and any others not already cleared at a lower level
- [ ] 5.2 Check drizzle migrations and queries still match (wallet-api tests, `openapi:check`)
- [ ] 5.3 `pnpm install`; run the per-level gates; fix regressions before moving on

## 6. Critical severity

- [ ] 6.1 Bump `happy-dom` → ≥20.8.9 wherever it is a direct devDependency (wallet-kit, wallet-transport, and any other vitest package) and fix the test environment where needed
- [ ] 6.2 Clear the remaining critical transitive packages: `pbkdf2`, `sha.js`, `form-data`, `handlebars`, `protobufjs` (scoped overrides per D2 if no parent fix)
- [ ] 6.3 `pnpm install`; run the per-level gates; fix regressions

## 7. Verification

- [ ] 7.1 `pnpm install --frozen-lockfile` succeeds with no lockfile change
- [ ] 7.2 Re-run `pnpm audit` and diff against the baseline: zero critical/high unless listed as accepted residuals with reasons
- [ ] 7.3 Run the full Playwright e2e suite on the final tree (fresh devnet, so it picks up the new addresses)
- [ ] 7.4 Add changesets per D6: `giano-contracts` for the new canonical addresses (flagged breaking for anyone who hard-coded paymaster addresses), plus any published package whose runtime dependency ranges moved

## 8. PR

- [ ] 8.1 Let the command open one draft PR via `ae-open-pr`, with its final report as the body (packages changed with advisories, accepted residuals, cooldown status and exclusions, Jira skipped), plus a "Contract addresses" section (old → new; chain 381185 test ERC-20 needs an operator redeploy)
- [ ] 8.2 Confirm the `ci`, `determinism` and `e2e` workflows are green on the PR
- [ ] 8.3 Announce in `#giano-dev`
