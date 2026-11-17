## Why

Giano's contracts are not deployed on any public chain with the current code, and nothing can be until a testnet
canonical deployer is configured (`DEPLOYERS.testnet` is `null`). Because of that, the `dev` environment is stuck on a
pre-CREATE3, EntryPoint v0.7 deployment (`infra/versions.json` `dev` = `5ba71241`, 355 commits behind `main`), and none
of the work since #132 can be rolled out to it.

The local stack and CI already run the current contracts (release `v3`, EntryPoint v0.9). They get them through
`local:deploy`, though, which installs CreateX and the EntryPoint itself, impersonates a placeholder deployer, grants
every role to one key and never deploys a timelock. The path a public testnet takes has never been run end to end:
- the wizard against real CreateX and EntryPoint code;
- a real class deployer;
- the provisioning wrapper;
- the timelock and the irreversible handoff;
- an upgrade through the timelock.

A review of that path, checked against the documentation, found that it would go wrong in ways that cannot be undone
on a public chain. The testnet profiles pin release `v2`, which the current wallet SDK no longer works with. A
timelocked upgrade leaves the deployment record stale. The handoff is checked only after it is sent.

This change rehearses the public deploy path locally, on a fork of Base Sepolia, then fixes what the rehearsal and
the review find. The goal is a platform proven to work on a public-path deployment of `v3`, with tooling ready for the
testnet and `dev` deployment. **The deployment itself is not part of this change.** It is prepared here and run later.

## What Changes

- **Local baseline.** Rebuild the local stack on current `main` and pass the e2e suite, so the rehearsal starts from a
  known-good platform.
- **A guarded fork rehearsal.** A testnet-class deployment can be rehearsed on an anvil fork of a public testnet, with
  a throwaway deployer instead of the unset canonical one. The rehearsal runs the whole public path:
  1. deploy `v3`;
  2. provision;
  3. deploy the timelock and hand off;
  4. upgrade through the timelock;
  5. run the doctor;
  6. point the local platform at the fork and smoke-test it.

  The override is accepted only on an anvil fork, and the rehearsal never writes to the committed deployment records,
  the address registry or the shipped profiles. It runs before the fixes, to confirm the findings, and after them, as
  the gate.
- **Profiles pin the current release.** Both testnet profiles move from `v2` to `v3`. CI fails when a profile with no
  deployment record pins anything older than the newest release. With `v2`, `signed_eth_call` fails, because the SDK
  signs the `v3` hash, and every new wallet on the chain would start on `v2` for good, since the factory's
  implementation is immutable. `v3` also carries the paymaster fixes from #222 and #227.
- **A timelocked paymaster upgrade is reconciled into the deployment record.** Today, after a timelock executes an
  upgrade, every later plan, provision, sponsorship run and the Helm verify Job fails with "proxy points at … not the
  planned implementation".
- **A handed-off chain verifies against its own profile.** After the handoff, the timelock holds `ROLE_ADMIN`, but the
  plan and the operator pre-checks still expect the bootstrap EOA, so every verification of a correctly handed-off
  chain would refuse. It was found behind the rehearsal's first failure. The profile's timelock now counts as the role admin.
- **Known mainnet chain IDs are always production chains.** Chain 1 can no longer be declared `testnet`, which would
  let the test fixtures through the R-29 guard.
- **One prerequisite check everywhere.** The low-level `deploy:cli core` runs the wizard's checks, the CreateX codehash
  and the canonical EntryPoint v0.9 runtime. `--entry-point` is local-only.
- **The doctor checks the right things.** It checks CreateX instead of the Arachnid factory, and treats a missing
  P-256 precompile as informational, since the wallet has a built-in fallback.
- **Provisioning supports the production role topology.** It takes the signer's public address, one holder per
  immediate role, and refuses grant-all on a mainnet.
- **Sponsorship rules install on a chain without the demo ERC-20.** `contracts:sponsorship` sent an empty allowlist
  there, on the belief that wallet management would still be sponsored. The wallet-api has always refused that write
  and sponsors nothing for an empty allowlist, so on every public chain the step failed. It was found behind D2 in
  the rehearsal. The operator now names the tenant's contracts in `SPONSOR_ALLOWLIST`, and the wrapper refuses to run
  without one.
- **The handoff is verified before it is sent.** The tool checks:
  - the timelock's code fingerprint;
  - that the proposers, executors and delays equal the profile's;
  - that every mainnet proposer is a contract. An EOA with an EIP-7702 delegation has code too and must not pass for
    a Safe. The rehearsal found that the doctor already makes this mistake.
- **RPC URLs are redacted in logs.**
- **Docs match the code**:
  - `docs/key-ceremony.md`, including the canonical deployer's real leak impact;
  - CHAIN-ADOPTION;
  - INFRASTRUCTURE §13.1;
  - PAYMASTER-SPECS (EVM `cancun`);
  - the contracts README.
- **A deploy-readiness package for testnet and `dev`, prepared but not executed**:
  - the operator checklist;
  - the `GIANO_CHAINS` and Terraform changes to make, written against the rehearsal's addresses;
  - the `dev` reset-or-migrate decision recorded;
  - the list of keys and funding to create.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `contract-deployment`:
  - Changed requirements: mainnet-list chains are production chains for R-29 and cannot be declared `testnet`.
  - New requirements:
    - A testnet deployment can be rehearsed on a fork.
    - Profiles pin the current release.
    - Timelocked upgrades are reconciled into the record.
    - Every core run checks the chain's prerequisites.
    - Provisioning supports separate role holders and a public signer address.
    - The handoff is verified before it is sent.
    - RPC URLs are redacted in output.
    - The doctor checks the prerequisites the contracts depend on.
- `production-key-ceremony`: the inventory states what a leaked canonical deployer can do, and that the key is reused
  for upgrade targets.

## Impact

- **Code:**
  - `packages/contracts/deploy/` (`config.ts`, `cli.ts`, `guided.ts`, `plan.ts`, `preflight.ts`, `deploy.ts`,
    `operations.ts`, `records.ts`)
  - `packages/contracts/scripts/doctor.ts`, `packages/contracts/scripts/provision-paymaster.ts`
  - `deploy/contracts/provision-paymaster.sh`, `deploy/contracts/operator.env.example`
  - `deploy/chains/*.json`
- **Rehearsal harness:** a script and a docker-compose override that run anvil as a Base Sepolia fork, and the
  platform services (wallet-api, bundler, wallet-web, paymaster-admin) against it.
- **Tests:** `packages/contracts/deploy/*.test.ts` (plan, preflight, profiles, deploy, operations), plus a new
  profile-release check in CI.
- **Docs:**
  - `docs/key-ceremony.md`, `docs/PAYMASTER-TIMELOCK-RUNBOOK.md`
  - `deploy/contracts/README.md`, `specs/CHAIN-ADOPTION.md`
  - `specs/INFRASTRUCTURE.md` §13.1, `specs/PAYMASTER-SPECS.md`
- **Package:** `@appliedblockchain/giano-contracts` (changeset: the deploy tooling and doctor are published with it).
- **No change on any public chain, and none to the `dev` environment, its secrets or `infra/versions.json`.**
- **Not in scope:**
  - The testnet and `dev` deployment itself: the canonical deployer key, real transactions, publishing the records,
    the cutover. This change prepares it.
  - Already known and tracked elsewhere:
    - owner-set convergence across chains (MC-32/MC-33; `specs/MULTICHAIN_SPECS.md` §10–11);
    - account recovery (BR-33);
    - OZ `validateUpgrade` (PAYMASTER-SPECS §4.4, deferred to the first upgrade);
    - production timelock delays;
    - a KMS/HSM signer for the deployer;
    - explorer source verification.
