## 1. Kick-off (command preamble)

- [x] 1.1 Run `/ae-dependency-vulnerability-fix` on branch `chore/dependency-vulnerability-fix` from a cleared context; answer its Jira prompt with "skip" (no Jira for this project) so the report records it
- [x] 1.2 Confirm the detected gates against design D4 and add the ones it misses (`wallet-api openapi:check`, ABI drift via `hh:compile` + `hh:wagmi`, `forge test`, determinism recompute, Playwright e2e)
- [x] 1.3 Confirm the package manager (pnpm 11.15.1) and the workspace map (12 packages; submodule lockfiles excluded)
- [x] 1.4 Record the cooldown finding: `minimumReleaseAge: 1440`, existing excludes `baseline-browser-mapping`, `postcss`

## 2. Baseline

- [x] 2.1 Save the baseline `pnpm audit --json` and the open Dependabot alerts (severity, package, manifest) to the scratchpad for the final diff
- [x] 2.2 Run every gate from D4 on the unmodified branch; record any pre-existing failure so it is not blamed on a bump
- [x] 2.3 For each advisory, work out its fix path (direct bump, parent bump, or scoped override) and assign each package to the lowest severity level it appears at (D3)

## 3. Low severity

- [x] 3.1 Fix low-only packages (`cookie`, `tmp`, `elliptic`, `diff`, `qs`, low `brace-expansion`), plus the multi-level packages whose lowest level is low (`handlebars`, `axios`, `undici`), each bumped to a version clearing all its advisories
- [x] 3.2 `pnpm install`; handle any cooldown block per package (wait or exclude by name, noted for the report)
- [x] 3.3 Run the per-level gates; fix regressions before moving on

## 4. Moderate severity — including OpenZeppelin

- [x] 4.1 Fix the remaining moderate packages: `uuid` in wallet-core, `fastify` (+ `@fastify/swagger-ui` 6 for `@fastify/static` 10) in wallet-api, `vitest` → ≥4.1.11 across the six vitest packages (with `@vitest/coverage-v8`), plus scoped overrides for the transitive moderate lines
- [x] 4.2 Adapt test config and test code to vitest 4 where the gates require it (none needed)
- [x] 4.3 Pin `@openzeppelin/contracts` and `@openzeppelin/contracts-upgradeable` exactly to 5.4.0
- [x] 4.4 Keep the wallet's addresses: serve `openzeppelin-contracts/contracts/utils/Base64.sol` from a byte-identical 5.3.0 copy in `vendor/` (file-level remapping, published with the package)
- [x] 4.5 Re-freeze the paymaster trio in `canonical.ts` from a fresh-anvil deploy; confirm factory and implementation are unchanged
- [x] 4.6 Upgrade the baked devnet paymaster in place (`devnet:upgrade:paymaster`) and update `docs/E2E-DEV-KEYS.md`
- [x] 4.7 Run the per-level gates, the storage-layout check and the determinism comparison

## 5. High severity

- [x] 5.1 Fix the high packages: `drizzle-orm` → ^0.45.2 in wallet-api and `happy-dom` → ^20.8.9 in wallet-kit and wallet-transport (its lowest advisory is high, per D3), plus scoped overrides for `@grpc/grpc-js`, `adm-zip`, `brace-expansion` 5, `browserslist`, `fast-uri` 3/4, `find-my-way`, `form-data` 2, `glob` 10, `immutable`, `minimatch` 3/5/9, `preact`, `socket.io-parser`
- [x] 5.2 drizzle ≥0.44 wraps driver errors in `DrizzleQueryError`: the ledger's unique-violation check now follows `cause`, so a duplicate reservation is refused again rather than thrown
- [x] 5.3 `pnpm install`; run the per-level gates; fix regressions before moving on

## 6. Critical severity

- [x] 6.1 Clear `pbkdf2` and `sha.js` (ethereum-cryptography, create-hash/hmac, @coinbase/wallet-sdk) with scoped overrides
- [x] 6.2 `pnpm install`; run the per-level gates; fix regressions

## 6a. Merge main (#122 paymaster ECDSA change, DHI, provisioner)

- [x] 6a.1 Resolve the four conflicts by taking main's side of the superseded Cancun re-freeze, then re-apply 4.4–4.6 on the merged sources
- [x] 6a.2 Rebuild `pnpm-lock.yaml` from main's lockfile with `pnpm install`; never hand-merge a lockfile
- [x] 6a.3 Clear advisories published since the first audit: `fast-copy` (moderate), `source-map-js` (high); record `braces` (high) and `sprintf-js` (moderate) as residuals with no patched release

## 7. Verification

- [x] 7.1 `pnpm install --frozen-lockfile` succeeds with no lockfile change
- [x] 7.2 Re-run `pnpm audit` and diff against the baseline: zero critical/high unless listed as accepted residuals with reasons
- [ ] 7.3 Bring up the e2e stack from the committed devnet state and run the full Playwright suite (proves the local environment works on the new addresses)
- [x] 7.4 Add changesets per D6: `giano-contracts` for the new canonical addresses (flagged breaking for anyone who hard-coded paymaster addresses), plus any published package whose runtime dependency ranges moved

## 8. PR

- [x] 8.1 Let the command open one draft PR via `ae-open-pr`, with its final report as the body (packages changed with advisories, accepted residuals, cooldown status and exclusions, Jira skipped), plus a "Contract addresses" section (old → new for each moved constant; live proxies to upgrade in place)
- [ ] 8.2 Confirm the `ci`, `determinism` and `e2e` workflows are green on the PR
- [ ] 8.3 Announce in `#giano-dev`
