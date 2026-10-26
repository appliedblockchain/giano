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
- Bump `@openzeppelin/contracts` and `@openzeppelin/contracts-upgradeable` 5.3.0 → 5.4.0 without moving any account
  address. The one OZ file the wallet compiles, `utils/Base64.sol`, changed only cosmetically in 5.4.0, but solc embeds
  every source file's hash in the bytecode. It is pinned to its 5.3.0 bytes in `vendor/openzeppelin-contracts-5.3.0/`, so
  the wallet factory and implementation keep their canonical addresses on every chain. The paymaster is rebuilt
  against 5.4.0: its fresh-deployment freeze moves, and existing proxies are upgraded in place through UUPS. (An earlier
  revision moved the EVM target to Cancun and re-froze everything; that became unnecessary once #122 replaced
  `SignatureChecker`, the import that pulled in the `mcopy`-using `Bytes.sol`.)
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
- **Contracts**: `remappings.txt` (pins `openzeppelin-contracts/contracts/utils/Base64.sol`), the vendored file (also
  published via `files`), `canonical.ts` (paymaster trio only), `generated.ts`, and the baked devnet `state.json` /
  `addresses.json`, upgraded in place with `devnet:upgrade:paymaster`. Live testnet paymaster proxies need an
  `hh:upgrade:paymaster` run to pick up the OZ 5.4 build; they keep their address.
- **Tests**: vitest 4 and happy-dom 20 may require test-config or test-code adjustments in the six vitest packages.
- **CI**: no workflow changes; the existing `ci`, `determinism` and `e2e` workflows are the regression gates.
