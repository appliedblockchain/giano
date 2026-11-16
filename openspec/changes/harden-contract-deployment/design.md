## Context

See proposal.md for the motivation. The deploy pipeline (#132, #199, G9) is mature: frozen releases, CREATE3 through
CreateX, release fingerprints, a guided wizard, per-class deployers, a mainnet deviation guard, and a timelock with
per-function delays and a doctor. Only its local shortcut has ever run:

```
local:deploy (CI, e2e, local stack)        public testnet path (never run end to end)
───────────────────────────────────        ──────────────────────────────────────────
installs CreateX + EntryPoint              must find the real ones (codehash checks)
impersonates 0x…dEaD, no key               class deployer key, its CREATE3 addresses
provision --grant-all-to anvil #0          contracts:provision wrapper
no timelock, no handoff                    contracts:timelock + contracts:handoff (irreversible)
no upgrade                                 upgrade through the timelock
```

Every finding below sits in the right-hand column. Each was checked against the documentation, and only gaps that are
not documented as deliberate are in scope:

| Finding | What the docs say | Disposition |
|---|---|---|
| Profiles pin `v2` | README §1 "pin v2 (already set)", written 27 Oct, before `v3` (#228, 5 Nov). #199 (10 Nov) kept `v2` without discussion. | Stale. Fix. |
| Timelocked upgrade leaves the record stale | Not covered. The `contract-deployment` spec assumes the record lists the target. | New. Fix. |
| Chain 1 can carry test fixtures | The `contract-deployment` spec covers the fixed list and `mainnet` declarations only. | Gap. Fix. |
| `deploy:cli core` weaker than the wizard | README: "expert primitive; use the wizard". CHAIN-ADOPTION step 4 and INFRASTRUCTURE §13.1 still prescribe it. | Known, but docs contradict. Fix both. |
| Provisioning collapses roles and needs the signer key | The script says `--grant-all-to` is development only. README says "use separate role holders otherwise". The wrapper cannot. | Partly known, no tool. Fix. |
| Handoff checked only after the fact | The runbook relies on the doctor afterwards. Production delays are pending sign-off (known). | Gap. Fix the pre-checks. Delays stay out of scope. |
| Doctor's P-256 and Arachnid checks | CHAIN-ADOPTION calls P-256 critical, but the wallet inlines FreshCryptoLib. The Arachnid check predates CreateX. | Wrong. Fix. |
| RPC URL logged | `values.yaml` says a keyed URL is fine. | Gap. Fix. |
| Deployer leak impact | key-ceremony: it "can occupy canonical addresses". | Understated. Fix the doc. Custody is an open question. |
| No way to run the public path before a real deploy | `DEPLOYERS.testnet` unset blocks every testnet-class run, including on a fork. | Gap. Add a guarded rehearsal. |
| Owner-set convergence, recovery, `validateUpgrade`, production delays, KMS deployer signer, explorer verification | Documented as not built or deferred. | Out of scope. |

## Goals / Non-Goals

**Goals:**
- Prove, locally, that the public deploy path works for `v3` and that the platform works on a deployment made that
  way: account creation, passkey signing, a sponsored transaction, the operator console.
- Make the tooling survive its own lifecycle: a timelocked upgrade must not break later runs.
- Make the production role topology possible, with one holder per role and an HSM-held signer.
- Leave the testnet and `dev` deployment fully prepared, so running it later is executing a checklist.

**Non-Goals:**
- Any transaction on a public chain, any change to the `dev` environment, and creating the canonical deployer key.
- Any change to Solidity or a new contract release. `v3` is deployed as is.
- Choosing the production delays, the production role holders, or mainnet deployer custody (see Open Questions).
- Building a migration tool for `dev`'s legacy v0.7 accounts. The readiness package records the reset-or-migrate
  decision.

## Decisions

### D0. Rehearse on an anvil fork with a guarded stand-in deployer
The rehearsal runs `anvil --fork-url <Base Sepolia RPC>`. The fork keeps chain ID 84532 and the real CreateX and
EntryPoint v0.9 code, so every check runs as it would on the real chain.
- **Deployer.** The canonical deployer is unset, so the rehearsal supplies a stand-in through
  `GIANO_REHEARSAL_DEPLOYER`. The tooling accepts it only when `anvil_nodeInfo` answers with a fork configuration.
  The stand-in is an anvil key, funded with `anvil_setBalance`.
- **Isolation.** The rehearsal copies the shipped profile into an ignored directory, `deploy/rehearsal/`, and runs
  with `--config`. The record and the address env file go there too. `gen:addresses` is not run.
- **Platform.** A compose override points the local services at the fork:
  - the bundler serves 84532 with an anvil executor key;
  - wallet-api's `GIANO_CHAINS` names the rehearsal's addresses explicitly;
  - postgres is fresh, with the local tenant fixtures, whose UUIDs provisioning registers on the fork.
- **Driver.** One script, `pnpm contracts:rehearse`, drives the whole sequence and prints a pass/fail per step, so the
  rehearsal before and after the fixes is the same run.
- *Alternative:* temporarily edit `DEPLOYERS.testnet` in a working copy. Rejected: it is easy to commit by accident,
  and it changes what `check:determinism` and the registry generator see.
- *Alternative:* rehearse on a non-fork anvil with chain ID 84532. Rejected: CreateX and the EntryPoint would have to
  be installed by our own code, which is exactly the shortcut the rehearsal exists to avoid.

### D1. Release pin rule: newest release while undeployed, frozen once recorded
A CI test reads every `deploy/chains/*.json`. For a profile whose chain has no `deployments/<chainId>.json`, the test
asserts that the profile pins the newest directory under `releases/`. Once a record exists, the pinned release must
equal the one in the record.
- *Alternative:* drop `release` from profiles and always use the newest release. Rejected: a re-run on a deployed
  chain must keep using the release it was deployed with, and the wizard's resume relies on it.

### D2. Reconcile upgrades from the proxy slot, not from a separate command
When the planner reads the proxy, it accepts an implementation address listed in `record.upgrades` that holds release
code, and treats it as the current `paymasterImplementation`. Runs that save the record write it back. This covers
timelock, Safe and direct execution with one rule.
- *Alternative:* a `deploy:cli upgrade --record` step after execution. Rejected: it is one more manual step that is
  forgotten exactly when it matters, and a timelock execution can be sent by anyone.

### D3. Mainnet-list chain IDs are both mainnet and production; `--network testnet` is refused for them
`PRODUCTION_CHAIN_IDS` becomes a superset of `MAINNET_CHAIN_IDS`. Network-class resolution refuses `testnet` for a
mainnet-list chain. That also stops a testnet deployer from placing contracts on Ethereum mainnet at the testnet
class's addresses.

### D4. One prerequisite check, shared by the wizard, `deploy:cli core` and the doctor
The CreateX codehash, the EntryPoint v0.9 runtime (chain-aware, as `preflight.ts` already does) and a Cancun probe are
extracted into one function that all three call. The doctor stops checking the Arachnid factory.
- **P-256:** reported as `info`, with gas guidance. `deploy:cli p256` stays as an optional gas optimisation. Its help
  text warns that it sends a pre-EIP-155 transaction, which some RPCs reject after the 0.1 ETH has already been sent.
- **Cancun probe:** an `eth_call` with a state override that runs `MCOPY`/`TLOAD`. A revert means no Cancun.

### D5. Provisioning takes addresses, never other people's keys
`provision-paymaster.sh` takes the following from the operator environment:
- `SPONSORSHIP_SIGNER_ADDRESS`, with `SPONSORSHIP_SIGNER_KEY` accepted only on local and testnet chains, for
  compatibility, and only to derive the address;
- `ROLE_HOLDER_<ROLE>` per immediate role, passed to the existing `--role-holder-<role>` flags of
  `provision-paymaster.ts`;
- `PAYMASTER_GRANT_ALL_TO` as the explicit opt-in for the development topology.

On a mainnet chain, grant-all and the defaulted tenant withdrawal address are refused. The rehearsal uses separate
holders, so the production topology is exercised.

### D6. The handoff pre-flight reuses the doctor's timelock checks
The doctor already asserts timelock roles and delays against the profile after the fact. The handoff runs the same
assertions, plus a `releaseOf` match on the timelock's code and a contract-account check on mainnet proposers, before it
sends anything. "Has code" is not enough: an EOA with an EIP-7702 delegation reports `0xef0100‖address` as its code.
The first rehearsal showed the doctor reporting such an EOA as "contract account, e.g. a Safe". One helper decides
"contract account" for the CLI, the handoff and the doctor. One implementation keeps the "before" and "after" checks from drifting apart. In the rehearsal the
proposer is an anvil account, which is acceptable on a testnet-class chain.

### D7. Redact at the single logging point
`deployerContext` and the doctor's `connect` print `new URL(url).origin`. Provider errors are already suppressed.

## Risks / Trade-offs

- **[Risk]** A fork rehearsal is not the real chain. Gas prices, the L1 data fee and RPC behaviour differ, and the
  fork freezes at its block. → The rehearsal proves correctness of the sequence and the platform, not costs. The
  readiness package keeps the README's gas reserves and the funding checks of the real run.
- **[Risk]** The fork depends on a public Base Sepolia RPC, which can rate-limit, and which serves only recent state,
  so an old block cannot be forked. → Accept a keyed URL (`--fork-url`, redacted by D7). Fork the latest block by
  default and print it; `--fork-block` pins one when the RPC is an archive node.
- **[Risk]** anvil's public development keys carry state strangers left on public testnets, EIP-7702 delegations
  included. → The rehearsal derives its own throwaway keys from fixed labels and funds them on the fork.
- **[Trade-off]** On the fork, the doctor found no RIP-7212 precompile (it reported the daimo verifier instead), so
  passkey checks there may take the slower path and cost more gas than on Base Sepolia itself. The rehearsal proves the
  sequence, not the costs.
- **[Risk]** The rehearsal override becomes a way to deploy with a non-canonical key on a real chain. → It is accepted
  only on an anvil fork, which is checked by RPC capability, not by a flag. A test covers the refusal.
- **[Risk]** The first real `v3` deployment is permanent for new wallets on each chain (the factory's implementation
  is immutable). → D1, the rehearsal gate, and a plan review before signing.
- **[Trade-off]** Refusing `--grant-all-to` on mainnet removes a shortcut that some demo flows use. Demos run on
  testnets, where it stays available behind the explicit opt-in.

## Validation Plan

1. **Baseline:** rebuild the local stack on current `main` (images, packages, devnet state) and pass the full e2e
   suite.
2. **Rehearsal, first pass:** build the harness (D0) and run it on unmodified tooling. Record each step's outcome. The
   expected failures are the `v2` pin (D1), provision after a timelocked upgrade (D2) and the doctor's P-256/Arachnid
   checks (D4). Anything else it finds is added to this change.
3. **Fix** (task groups 3–8).
4. **Rehearsal, gate:** rerun it. Every step passes:
   1. deploy `v3`;
   2. provision with separate holders;
   3. timelock and handoff;
   4. a timelocked upgrade, then a plan and provision that pass;
   5. the doctor;
   6. platform smoke on the fork: create an account, sign with a passkey, send a sponsored transaction, and check the
      operator console shows the tenant, balance and timelock.
5. **Readiness package:** turn the rehearsal's outputs into the testnet and `dev` checklist (task group 10).

Nothing here needs a rollback: no public chain or shared environment is touched.

## Open Questions

These do not change the specs or the tasks. They must be answered before the real deployment (mainnet for the first
two).
- **Mainnet canonical deployer custody.** Stay a development-team 1Password key out of ABIP-8 scope, or move into
  ceremony scope or a KMS signer, now that its leak impact is stated (production-key-ceremony delta)? This needs the
  tech lead and DevOps.
- **Production holders of the immediate roles.** Which Safes or keys hold `SIGNER_ADMIN`, `PAUSER`, `STAKE_ADMIN`,
  `TENANT_ADMIN`, `PARAM_ADMIN` and `FEE_COLLECTOR`?
- **`dev` legacy accounts.** A reset or a migration for the v0.7 test accounts (README §5). It is recorded in the
  readiness package and decided before the cutover.
- **Production timelock delays.** These need product sign-off, as the runbook already requires.
