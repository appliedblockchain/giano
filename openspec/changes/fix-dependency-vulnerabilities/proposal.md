## Why

`pnpm audit` against `pnpm-lock.yaml` reports 179 advisories (8 critical, 92 high, 67 moderate, 12 low) across ~70
distinct packages, and Dependabot shows the same picture (54 open alerts on the lockfile plus direct-dependency alerts in
`wallet-kit`, `wallet-transport`, `wallet-api` and `contracts`). The ticket (4 SP) is the card title itself — audit the
workspace's pnpm dependencies and fix them — so this change turns that into a checkable outcome and a repeatable method.

## What Changes

- Remediate every workspace package's dependency advisories, lowest severity first, using the
  `ae-dependency-vulnerability-fix` command's method: bump → `pnpm install` → regression gates → next level up.
- Bump direct dependencies with advisories, including majors where the fix requires it: `happy-dom` 17 → ≥20.8.9
  (critical; `wallet-kit`, `wallet-transport` and every vitest package that pulls it), `vitest` 3 → ≥4.1.11,
  `drizzle-orm` 0.43 → ≥0.45.2, `fastify` 5.10 → ≥5.12.1, `uuid` → ≥11.1.1 in `wallet-core`.
- Resolve transitive advisories by bumping the parent where possible, otherwise by pinned entries in the
  `pnpm-workspace.yaml` `overrides` block (the existing mechanism, today carrying `human-id` and `zod-to-json-schema`).
- **BREAKING (contract addresses)**: bump `@openzeppelin/contracts` and `@openzeppelin/contracts-upgradeable`
  5.3.0 → ≥5.4.0. OZ is compiled into `GianoPaymaster`, `GianoPaymasterDeployer` and `PrivateERC20`, so their bytecode —
  and therefore their CREATE2 addresses — change. This produces a new canonical freeze for the paymaster trio
  (`CANONICAL_SPONSORSHIP_PAYMASTER`, `…_IMPLEMENTATION`, `CANONICAL_PAYMASTER_DEPLOYER`) and a new test ERC-20 address.
  The smart-account factory and implementation do not import OZ, so **user account addresses do not move**. Approved by
  the product owner on 2026-09-29 ("it's ok to change the addresses right now").
- Keep the supply-chain cooldown (`minimumReleaseAge: 1440`). A fixed version younger than 24h is either waited out or
  added to `minimumReleaseAgeExclude` per package, decided case by case — never by lowering the threshold.
- Ship one PR whose description is the command's final report: packages changed (each paired with its advisory),
  unaddressed advisories with reasons, and the cooldown status.

## Capabilities

### New Capabilities
- `dependency-security`: the bar the workspace's dependency tree must meet at merge (no unaddressed critical/high
  advisories, every residual one documented with a reason), how remediation is gated, how the release-age cooldown is
  preserved, and how an address-moving dependency bump is carried through the canonical freeze.

### Modified Capabilities
<!-- None. test-erc20-registry keeps its requirements (one deterministic address on every testing chain, exposed via the
     registry); only the address value changes, which is data, not a requirement. -->

## Impact

- **Manifests**: all 12 workspace `package.json` files may change; `pnpm-lock.yaml` regenerated;
  `pnpm-workspace.yaml` `overrides` / `minimumReleaseAgeExclude` extended.
- **Out of scope**: the `package-lock.json` / `yarn.lock` files inside git submodules (`packages/contracts/lib/*`,
  `vendor/account-abstraction`) — upstream code we pin by commit, not install from.
- **Contracts**: `packages/contracts/canonical.ts`, `addresses.ts` (test ERC-20 per chain), `generated.ts`, e2e devnet
  `addresses.json` / `state.json`, and every place the old paymaster address is hard-coded (`deploy/docker-compose.*.yml`,
  `infra/iac/ecs_services.vars.tf`, `services/paymaster-admin/public/config.json`, `docs/E2E-DEV-KEYS.md`,
  `packages/paymaster-sdk/test/client-logs.test.ts`). The committed test ERC-20 on chain 381185 goes stale and needs an
  operator redeploy; no committed chain carries a paymaster deployment yet.
- **Tests**: vitest 4 and happy-dom 20 may require test-config or test-code adjustments in the six vitest packages.
- **CI**: no workflow changes; the existing `ci`, `determinism` and `e2e` workflows are the regression gates.
