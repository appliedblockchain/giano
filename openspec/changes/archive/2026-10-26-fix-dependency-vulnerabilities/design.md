## Context

See proposal.md (Why) for the numbers. What shapes the approach:

- **One lockfile, twelve workspace packages** (`pnpm-workspace.yaml`: root, `packages/*`, `services/*`, `e2e`), pnpm
  11.15.1 pinned through `packageManager`. Two advisory clusters dominate: the Hardhat 2 toolchain under
  `packages/contracts` (axios, form-data, handlebars, pbkdf2, sha.js, undici, tmp, cookie, …) and the gRPC/protobufjs
  stack under `services/wallet-api`. Direct-dependency advisories are few: `happy-dom` 17.6.3 (critical),
  `drizzle-orm` 0.43.1, `fastify` 5.10.0, `vitest` 3.2.7, `uuid` in `wallet-core`, and OZ 5.3.0.
- **Every advisory in the baseline audit had a patched version.** Advisories published while the PR was open (`braces`, `sprintf-js`) do not.
- **Cooldown**: `minimumReleaseAge: 1440`, with `baseline-browser-mapping` and `postcss` already excluded.
- **Contracts**: OZ is imported only by `GianoPaymaster.sol`, `GianoPaymasterDeployer.sol` and
  `testing/PrivateERC20.sol`. The wallet factory and implementation are Solady-based, so their canonical addresses stay
  put. Frozen values live in `canonical.ts`; the `determinism` workflow recompiles, redeploys on a fresh anvil and
  compares against it.
- **No Jira** for this project (the team tracks tickets in Notion); PRs are announced in `#giano-dev`.

## Goals / Non-Goals

**Goals:**
- Meet the `dependency-security` bar with the fewest and smallest version moves that do it.
- Keep every change attributable: each bump or override is traced to the advisory it fixes in the final report.

**Non-Goals:**
- Migrating `packages/contracts` from Hardhat 2 to Hardhat 3, or replacing the gas reporter / toolbox plugins. If an
  advisory can only be fixed that way, it becomes an accepted residual with a follow-up.
- Routine "latest everything" upgrades of packages with no advisory.
- Adding an audit gate to CI or a Dependabot config. Worth doing next, but it is a policy change for the team.
- Remediating lockfiles inside git submodules.

## Decisions

**D1 — The `ae-dependency-vulnerability-fix` command drives the work; tasks.md mirrors its stages.**
The command already covers what the ticket needs: enumerate the workspace, source findings from Dependabot, fall back
to `pnpm audit`, fix lowest severity first with gates between levels, handle the cooldown per package, and open one PR
whose body is the report. Re-deriving that by hand would just drift from the team's shared method. Two local
adjustments: its Jira step is answered "skip" (recorded in the report), and the OZ re-freeze (D5) is an extra step it
doesn't know about. *Alternative*: a Renovate or Dependabot bulk-update PR — rejected because it neither gates by
severity nor handles the canonical freeze.

**D2 — Fix at the parent first, override second.**
For a transitive advisory, first try a semver-compatible bump of the direct dependency that pulls it in. Only if the
parent has no fixed release in range, add an entry to the `overrides` block in `pnpm-workspace.yaml`, scoped with a
selector (`"axios@<1.12.0": "^1.12.0"`, or `"parent>child"`), so the override only lifts vulnerable ranges and never
forces a major onto a consumer that is already fine. Each override gets a trailing comment naming its advisory, so it
can be removed once the parent catches up. *Alternative*: blanket unscoped overrides — rejected because they cross
majors silently (e.g. `glob` 7 → 10 under Hardhat's `mocha`).

**D3 — Severity order is by the advisory, not the package.**
A package with advisories at several levels (`handlebars` low → critical, `axios` low → high) is bumped once, at the
**lowest** level where it appears, straight to a version that clears all of its advisories. This avoids bumping the same
package three times. It also means OZ (moderate) and vitest (moderate) land before happy-dom (critical), which fits the
command's intent: the riskier changes are separated out and each one is gated on its own.

**D4 — Gate set and baseline.**
Per level: `pnpm install` (the command's own step), then the CI job commands — `build` for every package that has one,
`test` for wallet-core, wallet-transport, tx-describe, wallet-kit, paymaster-sdk and wallet-api, `typecheck` for
wallet-api, wallet-kit, wallet-web, paymaster-admin and custom-example, `lint` for custom-example,
`wallet-api openapi:check`, `hh:compile` + `hh:wagmi` with no `generated.ts` drift, and `forge test`. Additionally: the
determinism recompute after the OZ level, and the Playwright e2e suite once on the final tree. Before the first bump,
the gates run on the unmodified branch. A gate that already fails there is recorded as pre-existing and never blamed on
a bump.

**D5 — Keep account addresses: pin the one non-functional OZ change the wallet compiles.**
The wallet imports OZ only through `openzeppelin-contracts/contracts/utils/Base64.sol` (from webauthn-sol and
`GianoSmartWallet`). 5.4.0 changed that file only cosmetically, but solc's metadata hash covers every source file, so
the bump alone would move the factory and implementation on any EVM target. A file-level remapping serves that import
from a byte-identical copy of the 5.3.0 file in `vendor/openzeppelin-contracts-5.3.0/`, with a README explaining it.
Hardhat passes no remappings into solc metadata, so the wallet bytecode is unchanged, which was verified by a fresh
deploy landing on `0x26dC…7050` / `0x15cC…ea56`. Both OZ packages are pinned exactly to 5.4.0.
*Alternatives rejected*: moving the EVM target to Cancun and re-freezing everything (the first revision of this change,
forced by `SignatureChecker` → `Bytes.sol` → `mcopy`; that dependency went away when #122 switched the paymaster to
`ECDSA`); and re-freezing the wallet on `paris`, which would strand every account address for a formatting diff.

**D5a — The paymaster re-freezes for fresh deployments only.** The paymaster genuinely compiles OZ 5.4 code, so
`CANONICAL_SPONSORSHIP_PAYMASTER`, its implementation and the deployer move (`0x5Eaf…`, `0x4046…`, `0x2bB9…`). Following
#122, existing proxies keep their funding address: the baked devnet proxy (`0xf98b…0718`) is upgraded in place with
`devnet:upgrade:paymaster`, and live testnet proxies get `hh:upgrade:paymaster`.

**D6 — Changesets.** `giano-contracts` gets a patch, as #122 did for its paymaster re-freeze;
The published packages whose shipped constants or dependency ranges change (`giano-contracts` for the new canonical
addresses, and any published package whose runtime deps move) get a changeset. The address move is described as
breaking for anyone who hard-coded the old paymaster addresses.

**D7 — PR mechanics.** One PR from `chore/dependency-vulnerability-fix`, opened as a draft via `ae-open-pr` (the command
delegates to it). The body is the command's final report, plus a "Contract addresses" section listing old → new for each
moved constant and the live proxies that need an in-place upgrade.

## Risks / Trade-offs

- [vitest 3 → 4 / happy-dom 17 → 20 break test setup across six packages] → They land in separate levels (moderate,
  then critical), so a failure points to one bump. Follow each package's migration notes and fix test config there,
  not with pins that bring the advisory back.
- [An override pushes a Hardhat 2 plugin onto an incompatible transitive major] → D2's scoped selectors, plus
  `hh:compile`, `forge test` and the ABI-drift check as gates. If it still breaks, record it as a residual rather than
  fork the toolchain.
- [fastify / drizzle-orm minors change behaviour in wallet-api] → the wallet-api test suite, `openapi:check`, and the
  e2e run (the real API behind the real wallet) cover it.
- [The cooldown blocks a patched version] → Ask per package (the command's "Age block" prompt). The default answer is
  to wait if the version is < 24h old and the fix isn't critical, otherwise exclude it by name.
- [Stale addresses survive somewhere the grep misses, such as runtime env in deployed environments] → The report lists
  every moved address, and deployed environments pick up the new paymaster through their env vars; flag this in the PR
  for whoever owns the ECS/Helm values.
- [Scope grows past 4 SP because of the Hardhat tree] → The non-goal on a Hardhat 3 migration caps it. Anything past
  that becomes a documented residual.

## Migration Plan

1. Merge the PR. Local and e2e stacks come up on the upgraded devnet state with no extra steps.
2. Upgrade the live testnet paymaster proxies (Base Sepolia, Sepolia) with `hh:upgrade:paymaster` to pick up the
   OZ 5.4 build. The proxy address and tenant balances are unchanged.

Rollback: revert the PR. No account or proxy address depends on it.

## Open Questions

- Who runs the testnet paymaster upgrades? This can be settled at PR review; it doesn't change the work.
