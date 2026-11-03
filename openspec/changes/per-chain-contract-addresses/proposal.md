# Proposal

## Why

Giano's contracts tooling and services assume one canonical deployer for every chain. Every contract address is
CREATE3(`CANONICAL_DEPLOYER`, label), frozen as constants in `canonical.ts` (`CANONICAL_FACTORY`,
`CANONICAL_IMPLEMENTATION`, `CANONICAL_SPONSORSHIP_PAYMASTER`, and `CANONICAL_CODE`, which is keyed by address).
`gen:addresses`, the deploy CLI and wizard, `giano-doctor` and wallet-api's boot-time chain check all refuse any other
address (MC-19).

We now want two canonical deployers, one for testnets and one for mainnets. A testnet key adopts testnets freely and a
compromise of it never touches mainnet. With two deployers the same label resolves to different addresses on testnets
and mainnets, so no single constant can be "the" address. We also want to be able to deviate on a single chain, for
example a contract already deployed elsewhere, or a chain where the deterministic route is unavailable. The latest
release (`v2`) has not been deployed anywhere yet, and the real deployer addresses are not known until the keys
are created. This is the cheapest time to stop the system from expecting specific addresses.

## What Changes

- **BREAKING (contracts package):** remove the address constants `CANONICAL_FACTORY`, `CANONICAL_IMPLEMENTATION`,
  `CANONICAL_SPONSORSHIP_PAYMASTER`, `CANONICAL_SPONSORSHIP_PAYMASTER_IMPLEMENTATION` and `CANONICAL_DEPLOYER`, and the
  address-keyed `CANONICAL_CODE`, from the published package. The per-chain registry (`addresses.ts`, generated from
  the deployment records plus overrides) becomes the only source of contract addresses.
- **Verify code independently of the address.** Each release publishes, per contract, a code fingerprint: the runtime
  code hash with immutable values masked. Verification checks code against the fingerprint wherever the contract
  sits, and checks immutables (the factory's implementation, the wallet's EntryPoint) semantically.
- **One deployer per network class.** `deploy/config.ts` declares a `mainnet` and a `testnet` canonical deployer.
  Each chain profile declares its class. Local chains keep an impersonated local deployer, so the devnet and e2e no
  longer move when a real deployer is set.
- **Deterministic by default, overridable per chain.** By default every chain in a class gets the class's CREATE3
  addresses, so all mainnets share addresses. A chain profile can override individual contract addresses. The
  deployment record notes every address that deviates from the deterministic one.
- **Mainnet deployment guard.** For a mainnet profile, the deploy wizard requires the mainnet canonical deployer's key
  and plans the deterministic addresses. Any deviation (an override, or a signing key other than the canonical
  deployer's) prints a warning that names each affected contract with its expected and actual address, and needs an
  exact-text confirmation. Non-interactive runs refuse to deviate. Testnet deviations are reported, not gated.
- **wallet-api and doctor generalise.** Chain admission checks the chain's configured or registered addresses: the
  code there must be a release's, the factory's implementation must be the registered one, and served chains'
  factories must derive the same account for the probe owner (the existing MC-22 cross-check, which stays). Nothing
  compares against a constant address.
- Amend MC-17, MC-19, MC-20, MC-27 and MC-28 (`specs/MULTICHAIN_REQUIREMENTS.md`). Update `specs/CHAIN-ADOPTION.md`,
  the contracts README, `deploy/contracts/README.md` and `docs/key-ceremony.md`.

Out of scope: per-chain wallet addresses. Once a factory is deployed on a production chain it does not change, so one
wallet address per credential (MC-16, MC-24) still holds within a deployment, and wallet-api's storage is unchanged.

## Capabilities

### New Capabilities
- `contract-address-registry`: where every Giano contract address on a chain comes from (deployment records plus
  per-chain overrides), how consumers resolve it per chain, and how code is verified at an arbitrary address against a
  release.
- `contract-deployment`: how a chain is adopted. This covers the canonical deployer per network class, deterministic
  addresses with per-chain overrides, the mainnet key and deviation guard, and the deployment record.

### Modified Capabilities
- `production-key-ceremony`: the canonical deployers become two development-team keys (mainnet and testnet), kept
  in 1Password and outside ABIP-8 scope, instead of one ceremony key that adopts every chain.

## Impact

- `packages/contracts`: `deploy/config.ts`, `deploy/create3.ts`, `deploy/cli.ts`, `deploy/guided.ts`,
  `deploy/preflight.ts`, `deploy/profiles.ts`, `deploy/records.ts`, `deploy/operations.ts`, `scripts/doctor.ts`,
  `scripts/generate-canonical.ts` (replaced by a release-fingerprint generator), `scripts/generate-addresses.ts`,
  `scripts/deploy-local.ts`, `canonical.ts`, `index.ts`. Published API: a major version bump, with a changeset.
- `deploy/chains/*.json`: a new `network` field and an optional `addresses` override block. Profiles move to release
  `v2`. Mainnet profiles are added when their chains are chosen.
- `services/wallet-api`: `src/services/chain-verify.ts`, `openapi/generate.ts`, tests.
- CI: `determinism.yml` asserts the CREATE3 math per class and fingerprint drift instead of the frozen addresses.
- e2e/devnet: regenerated once, against the local deployer. After that, setting a real deployer does not touch them.
- Docs and specs listed above. No database migration, and no SDK (`wallet-core`, `wallet-kit`, `connector`) API
  change: they already resolve addresses per chain through the registry or `GIANO_CHAINS`.
