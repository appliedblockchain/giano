# Design

## Context

See proposal.md for the motivation. Current state, at `main` 66df0d9:

- `deploy/config.ts` holds one `CANONICAL_DEPLOYER` (placeholder `0x…dEaD`) and the fixed labels. `deploy/create3.ts`
  derives every address as CREATE3 through CreateX with a permissioned salt (`deployer ‖ 0x00 ‖ keccak(label)[0:11]`).
- `scripts/generate-canonical.ts` deploys every release on a throwaway anvil, impersonating the deployer, and writes
  `canonical.ts`. That file holds the address constants plus `CANONICAL_CODE`, the runtime code hash each release leaves
  **at each address**. Code hashes are per address because runtime code embeds immutables: the factory's
  `implementation`, and the UUPS `__self` in both implementations.
- These consumers compare against the constants:
  - `generate-addresses.ts` refuses records signed by another deployer, and refuses code not in `CANONICAL_CODE`;
  - `deploy/cli.ts` and `deploy/guided.ts` refuse to sign while the deployer is the placeholder, and refuse any other
    key;
  - `scripts/doctor.ts` checks that the factory, implementation and paymaster are "canonical";
  - wallet-api's `chain-verify.ts` raises `factory-not-canonical`, `implementation-mismatch` (against
    `CANONICAL_IMPLEMENTATION`) and `code-not-canonical`;
  - `openapi/generate.ts` uses `CANONICAL_FACTORY` as a stand-in env value.
- wallet-api already resolves each chain's factory and paymaster from `GIANO_CHAINS`, falling back to the registry
  (`config.ts`). It already performs the MC-22 probe cross-check. The SDK packages already use the per-chain registry.
- Chain profiles (`deploy/chains/*.json`, schema in `deploy/profiles.ts`) cover only Base Sepolia and Ethereum Sepolia,
  pinned to release `v1`.
- Nothing has been deployed to a public chain, so no record or address has to be migrated.

## Goals / Non-Goals

**Goals:**
- No runtime or tooling check that depends on a contract being at a particular address. Verification is by code
  fingerprint plus semantic immutable checks.
- Deterministic addresses stay the default path, per network class.
- The mainnet path makes a deviation hard to do by accident and impossible to do silently.
- The devnet and e2e stop depending on the real deployers.

**Non-Goals:**
- Per-chain wallet addresses for one credential. MC-16 and MC-24 stand; factories do not change once on production.
- A KMS/HSM signing adapter for the deploy wizard. This is a separate gap in `deploy/contracts/README.md`.
- Choosing which mainnet chains to adopt, or their profiles' operational values.
- Removing a chain from the R-29 fixture protection list. Protection is widened instead (D8).

## Decisions

### D1. Release code fingerprints replace address-keyed code hashes
For each release and deployable contract, compile the release's committed `standard-input.json` with the solc it
names. `release:verify` already does this. Read `evm.deployedBytecode.immutableReferences` and the runtime bytecode.
Publish `{ contract, release, immutables: [{start, length}], fingerprint }`, where `fingerprint` is the keccak256 of
the runtime code with every immutable range zeroed. A generated, committed `releases.ts` replaces `canonical.ts`. It
exports a `releaseOf(kind, runtimeCode, address?)` helper that applies each candidate's mask and compares hashes.

A masked range can hold anything, so `releaseOf` also checks the masked values themselves:
- every range of one immutable SHALL hold the same value. The factory reads `implementation` in four places, and code
  whose getter returns one implementation while `createAccount` clones another is not release code;
- every UUPS `__self` range SHALL hold the contract's own address. Callers pass the address the code was read from,
  and code copied from another address, or with a modified `__self`, is refused. A wrong `__self` would make every
  UUPS upgrade of the paymaster revert.

Immutables are then checked semantically, against the chain's registry:
- `factory.implementation()` must equal the registered wallet implementation;
- the wallet implementation's `entryPoint()` must equal the chain's EntryPoint (already done);
- the paymaster proxy's runtime must itself be release `ERC1967Proxy` code, and its ERC-1967 implementation slot must
  hold paymaster release code. Checking the slot alone is not enough: any contract can write a genuine implementation
  into that slot without delegating to it.

With the `__self` check above, masking `__self` loses nothing.

*Alternatives:*
- Keep deploying on anvil, but at the chain's actual addresses. This needs a per-chain regeneration step and still
  ties verification to the address.
- Trust the code hash written in the deployment record. This verifies against a committed file rather than the chain
  (MC-20), and is rejected.
- Diff two anvil deployments to locate immutables. This is fragile, because constructor arguments also differ.

### D2. Deployers per network class, with a fixed local deployer
`deploy/config.ts` exports `DEPLOYERS: { mainnet: Address | null; testnet: Address | null; local: Address }`. `local`
stays `0x…dEaD` permanently and is only ever impersonated. `null` means "not yet set": the tooling plans,
but refuses to sign. A runtime check rejects two configured deployers with the same address, compared
case-insensitively. Unset (`null`) deployers are skipped, so the shipped configuration, with both unset, loads. Because local chains use their own deployer, the
devnet state, `e2e/devnet/addresses.json` and the hardcoded devnet pins stay as they are. The README's "switching to
the real deployer" procedure, with its devnet regeneration, goes away.

*Alternative:* derive the class from the chain id with a hardcoded mainnet list. Rejected: the profile is already the
per-chain source of truth, and an explicit field is reviewable.

### D3. Profile schema: `network` and `addresses`
Add a required `network: "mainnet" | "testnet"` to the profile, and an optional
`addresses: Partial<Record<"walletImplementation" | "factory" | "paymasterImplementation" | "paymasterProxy",
Address>>`. The timelock is not an override key. It is deployed with plain CREATE by `deploy:cli timelock`, it has no
deterministic address, and its address already lives in `profile.timelock.address` (G9). A second source for it
would let the two disagree. An override means "this contract already exists here, so verify and record it; do not deploy
it". Contracts that depend on an overridden one use the override address. For example, the factory's constructor takes
the overridden wallet implementation, and the proxy is initialised with the overridden paymaster implementation.

An overridden contract is verified before it is adopted, not only for release code:
- an overridden factory SHALL clone the planned wallet implementation;
- an overridden paymaster proxy SHALL point at the planned paymaster implementation. When only the proxy is
  overridden, the planned implementation is the deterministic one, and a proxy that points elsewhere is refused with
  a hint to override `paymasterImplementation` as well;
- an overridden paymaster proxy SHALL have the profile's EntryPoint and fee parameters, and the planned `ROLE_ADMIN`
  SHALL hold `ROLE_ADMIN` on it (the same `verifyCoreState` check an existing deterministic proxy gets).
Unknown keys stay refused, matching the profile schema's existing strictness. The existing profiles gain
`"network": "testnet"` and move to release `v2`.

### D4. Planning computes expected and actual addresses, then classifies deviations
The wizard and `deploy:cli` build a plan per contract: the expected address (CREATE3 of the class deployer and the
label), the actual address (the override, or CREATE3 of the signing key's address and the label), and the code found
there. Either address can be unresolved, shown as `(none)` or `(unknown)`:
- the expected address is unresolved while the class deployer is `null`. The plan then marks no deviation and carries
  the "deployer not configured" blocker;
- a keyless plan (`--plan`, or a verify-only run) uses the expected address as the actual one, so a read-only plan
  works whenever the class deployer is set. With neither a deployer nor a key, the actual address is unresolved, and
  its code is reported as not checked. A deviation is any contract whose actual address differs from its expected one. If the signing key is not the
class deployer, every contract it would deploy is a deviation. Note that CreateX's permissioned salt makes a different
signer land at different addresses anyway: the tooling has to state that, not hide it.

For `mainnet`, a deviation:
- triggers a warning block, listing each contract's expected and actual address and the reason (an override, a
  non-canonical signer, or unexpected existing code);
- requires the operator to type `deviate <profile name>`, in addition to the existing `deploy <network> <release>`
  confirmation;
- makes non-interactive runs exit non-zero.

For `testnet`, the plan shows deviations, and the only gate is the existing confirmation. The low-level
`deploy:cli core` has no prompt, so it always refuses a mainnet deployment that deviates and points the operator at
the guided wizard. There is no flag that skips the typed confirmation.

*Alternative:* refuse non-canonical signers on mainnet outright. Rejected by the product owner, who chose to warn on
deviation and require confirmation.

### D5. Deployment record v2
Records gain `network` and per-contract `deterministic: boolean`, `expected` and `fingerprint`, plus a `deviations`
array with the confirmed reason and timestamp. `deployer` stays the signer's address. `codehash` stays the raw
`keccak256` of the runtime code, for integrity. `fingerprint` is the masked hash: the deploy tooling runs `releaseOf`
against the chain's code, at the contract's address, when it writes the record. `gen:addresses` cannot re-mask a
hash, so it checks the recorded fingerprint instead. It checks the following:
- the required contracts are present;
- each recorded fingerprint is a release fingerprint of that contract, for the release the record names;
- `address-overrides.json` sets only third-party addresses (the EntryPoint). An entry for a Giano contract is refused,
  because nothing verified it. A Giano contract at a non-deterministic address enters the registry only through a
  profile override, which the deploy tooling verifies and records.

It no longer rejects a non-canonical deployer or address. Records written before this change exist only for local
chains, which are never committed, so no reader needs the old format.

### D6. wallet-api and doctor verify against the chain's own addresses
`chain-verify.ts` drops `factory-not-canonical`. It renames `code-not-canonical` to `code-not-release` and adds the
contract kind. `implementation-mismatch` now compares the factory's `implementation()` with the chain's resolved
implementation, which comes from `GIANO_CHAINS` `walletApi.implementation` or the registry. The probe cross-check
across served chains stays as the identity guard. It applies to every admission, not only the boot-time one: a chain
that was unreachable at boot and recovers later is compared with the probe address of the chains already served, and
a mismatch keeps it unavailable and raises an alert. The first chain to be admitted sets the reference, so recoveries
that come back concurrently are compared with each other too.

For chains outside the registry (the local chains), `walletApi.implementation` is the only source of the wallet
implementation. When it is absent, the factory's clone target is still checked for release code and EntryPoint, and
wallet-api logs that the implementation comparison was skipped. The shipped dev and e2e configurations set it. `doctor` reports each address together with whether it matches the
class's deterministic address. That is information, not a failure, because doctor has no profile in general. With
`--chain <profile>` (`contracts:doctor`) it also flags mainnet deviations that the record does not list.
`openapi/generate.ts` uses a fixed dummy address.

### D8. The deployer holds no authority, and R-29 follows the network class
The custody decision for the deployer keys (development team, 1Password, outside ABIP-8) holds only while a deployer
key has no authority on any deployed contract. The deploy tooling SHALL therefore refuse a paymaster `ROLE_ADMIN` that
is the signing key or a configured class deployer, on every non-local chain. Override verification SHALL refuse a
paymaster proxy on which the signer or a class deployer holds `ROLE_ADMIN`.

R-29's fixed list (`8453, 84532, 11155111`) stays. A chain whose profile or record says `network: "mainnet"` is also
protected: `deploy:cli testing` refuses it, `gen:addresses` refuses test fixtures in its record, and `doctor --chain
<profile>` fails a test paymaster on it. Adopting a mainnet therefore needs no code change to be protected.

### D7. CI
`determinism.yml`:
- regenerates `releases.ts` and fails on drift;
- for each class deployer that is set, deploys the current release on anvil through CreateX, impersonating that
  deployer, and asserts that the addresses equal the CREATE3 math and the code passes `releaseOf`;
- runs the same for `local` unconditionally.

`ci.yml`'s `addresses.ts` drift check stays.

## Risks / Trade-offs

- [A masked fingerprint accepts any value in an immutable slot] → Every immutable that matters is checked
  semantically (D1). A new contract or release that adds an immutable must add its semantic check. A unit test fails
  when a release has an immutable reference whose check is not registered.
- [Operators can confirm a deviation on mainnet and split the mainnet address set] → An exact phrase is required, the
  record keeps the deviation permanently, doctor surfaces it, and wallet-api still refuses factories that derive
  different wallets.
- [The probe check compares the chains served now, not the wallets already stored] → Replacing every served chain at
  once with factories of another derivation would pass the probe check, while existing users keep wallet addresses
  the new factories do not derive. This is not new: the canonical constants did not stop it either, because a
  deployment could change them by upgrading the package. It is out of scope here (factories do not change once on
  production, MC-24). A follow-up persists the deployment's probe address in the database and refuses to start when
  it changes without a migration.
- [Testnet and mainnet wallet addresses differ for the same passkey] → Accepted. Within a deployment every served
  chain shares one factory derivation, which the probe check verifies. Integrator docs (MC-31) are updated to say
  identity holds within a network class.
- [Removing exports breaks consumers of the contracts package] → A major version, a changeset that names the
  replacements (`getGianoDeployment(chainId)` and `releaseOf`), and an in-repo grep shows the only consumers are
  wallet-api and the contracts scripts.
- [The release compile toolchain becomes a dependency of fingerprint generation] → It is already a CI dependency
  through `release:verify`. The generated file is committed, so consumers need no solc.

## Migration Plan

Nothing is deployed on a public chain, so there is no on-chain or record migration. The rollout is a `gh stack`:
1. this OpenSpec change;
2. contracts: fingerprints and verification (D1, D7);
3. contracts: classes, profiles, overrides, records and the deployment guard (D2–D5), with a major changeset;
4. wallet-api and doctor (D6);
5. docs and specs.

Each layer keeps CI green on its own. Once the development team has created both deployer keys in 1Password, a small
follow-up PR sets the `testnet` and `mainnet` addresses in `deploy/config.ts`, naming the 1Password items. That PR touches no generated devnet file. Rollback
before any public deployment is a revert of the stack.

## Open Questions

- Which mainnet chains to adopt first (Base 8453, Ethereum 1, others). Their profiles are added as data once chosen,
  with no code change.
- Which 1Password vault and items hold the two deployer keys. The specs only require 1Password and that the docs
  name the items.
