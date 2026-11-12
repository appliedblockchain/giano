## 1. Local baseline on current main

- [x] 1.1 Stop and remove the running e2e stack (`--remove-orphans`), rebuild every image from current `main`, and
      bring it up on the committed `v3` devnet state
- [x] 1.2 Rebuild the packages in dependency order (contracts `build:ts`, wallet-transport, tx-describe, wallet-core,
      wallet-kit, connector), and make sure no stale `dapp/serve.mjs` or `wallet-byo/serve.mjs` process is running
- [x] 1.3 Run the full Playwright suite and record the result. Fix or file anything red before going on
- [x] 1.4 Run `forge test` (install Foundry if needed) and `pnpm -F @appliedblockchain/giano-contracts test:deploy`
      and `test:deploy:integration`, and record the results

## 2. Rehearsal harness

- [x] 2.1 Accept `GIANO_REHEARSAL_DEPLOYER` as the class deployer only when `anvil_nodeInfo` reports a fork; refuse it
      on any other RPC; add tests for both
- [x] 2.2 Send rehearsal records, profile copies and address env files to an ignored `deploy/rehearsal/` directory,
      and skip `gen:addresses` there; add a test that committed files stay unchanged
- [x] 2.3 Add a compose override that runs anvil as a Base Sepolia fork at a pinned block, and points the bundler and
      wallet-api (explicit `GIANO_CHAINS`), wallet-web and paymaster-admin at it on a fresh database with the local
      tenant fixtures
- [x] 2.4 Add `pnpm contracts:rehearse` to drive the sequence and print a pass/fail line per step:
      1. fund the stand-in keys;
      2. plan, then deploy `v3`;
      3. provision with separate role holders;
      4. install the sponsorship rules;
      5. deploy the timelock, then the handoff;
      6. `upgrade --timelock` to the newest release's versioned target (`giano.paymaster.impl@vN`), then schedule from
         the proposer, warp past the delay and execute from another account;
      7. plan, keyless verify (`deploy:cli core` without a key, as the Helm Job runs it) and the provisioning refusal
         after the handoff;
      8. run `contracts:doctor`
- [x] 2.5 Add a platform smoke step on the fork: create an account, sign with a passkey, send a sponsored
      transaction, check the paymaster accounting, and check that the operator console reads the tenant, balance and
      timelock
      _Done except the console: the smoke checks the tenant's balance on-chain and the provisioning step reads it
      back through the admin API, but no step opens the operator console. Left for the testnet smoke (rollout
      step 11)._

## 3. Rehearsal, first pass (before fixes)

- [x] 3.1 Run the rehearsal on the profiles as committed (`v2`) and record each step's outcome
- [x] 3.2 Run it again with `--release v3`, to separate the release problem from the tooling problems, and record it
- [x] 3.3 Compare against the expected failures (D1, D2, D4); add any new finding to proposal, specs and tasks before
      fixing

## 4. Release pin

- [x] 4.1 Move `deploy/chains/base-sepolia.json` and `deploy/chains/ethereum-sepolia.json` from `v2` to `v3`
- [x] 4.2 Add a profiles test: an undeployed profile must pin the newest `releases/` entry, and a deployed one must pin
      its record's release

## 5. Upgrade reconciliation

- [x] 5.1 In the planner, accept a proxy implementation that is a recorded upgrade target holding release code, and
      treat it as the current `paymasterImplementation`
- [x] 5.2 Write the reconciled implementation back to the record on runs that save it (the registry regenerates from
      committed records only)
- [x] 5.3 Apply the same rule in `verifyCoreState` and in the operations' pre-checks (`contracts:provision`,
      `contracts:sponsorship`)
- [x] 5.5 Accept the profile's timelock as the `ROLE_ADMIN` holder in `verifyCoreState` once the profile names one
      (plan, keyless verify, operator pre-checks), and make provisioning say, after the handoff, that role changes go
      through the timelock
- [x] 5.4 Integration test on anvil: `upgrade --timelock`, execute through the timelock, then plan, provision and
      keyless verify all pass; an unrecorded implementation still blocks

## 6. Network class and prerequisites

- [x] 6.1 Make `PRODUCTION_CHAIN_IDS` include every `MAINNET_CHAIN_IDS` entry; refuse `--network testnet` and a
      `testnet` profile for a mainnet-list chain
- [x] 6.2 Extract one prerequisite check (CreateX codehash, EntryPoint v0.9 runtime, Cancun probe) and call it from
      the wizard, `deploy:cli core` and the doctor
- [x] 6.3 Refuse `--entry-point` on non-local chains
- [x] 6.4 Doctor: drop the Arachnid factory check, make missing P-256 support `info` with gas guidance, and remove the
      `scripts/p256_deploy.ts` reference
- [x] 6.5 `deploy:cli p256` help text: optional, sends a pre-EIP-155 transaction, check the RPC accepts one before
      funding
- [x] 6.6 Tests for chain 1 without a profile, a foreign CreateX codehash on the low-level path, and a P-256-less chain
      passing the doctor

## 7. Provisioning topology

- [x] 7.1 `provision-paymaster.sh`: take `SPONSORSHIP_SIGNER_ADDRESS`; allow `SPONSORSHIP_SIGNER_KEY` only on
      local and testnet chains
- [x] 7.2 Pass `ROLE_HOLDER_<ROLE>` through to `--role-holder-<role>`, and require `PAYMASTER_GRANT_ALL_TO` for the
      single-holder topology
- [x] 7.3 On a mainnet chain, refuse grant-all and an unset tenant withdrawal address
- [x] 7.4 Update `deploy/contracts/operator.env.example` and the e2e devnet generator to the new variables
- [x] 7.5 Tests for the signer given by address only, separate holders, and grant-all refused on a mainnet profile
- [x] 7.6 `contracts:sponsorship`: take the tenant's contracts from `SPONSOR_ALLOWLIST` and refuse an empty allowlist
      (N3); the rehearsal allow-lists a stand-in contract; test the refusal

## 8. Handoff pre-flight and output hygiene

- [x] 8.1 Share the doctor's timelock role and delay assertions with the handoff
- [x] 8.2 Before sending, check the timelock code with `releaseOf`, proposers and executors against the profile,
      delays at or above the published values, and the delay policy
- [x] 8.3 On a mainnet chain, refuse a proposer with no code or with only an EIP-7702 delegation designator; use the
      same contract-account helper in the doctor's proposer line and the CLI's timelock warning
- [x] 8.4 Tests for a proposer mismatch, an EOA proposer on mainnet, unrecognised timelock code, and short delays
- [x] 8.5 Print only the RPC origin in `deployerContext` and in the doctor's `connect`; add a test with a keyed URL

## 9. Rehearsal gate

- [x] 9.1 Rerun `pnpm contracts:rehearse` on the fixed tooling and the committed profiles; every step passes,
      including plan and provision after the timelocked upgrade
- [x] 9.2 Run the platform smoke on the fork, and record the transaction hashes and addresses in the PR
- [x] 9.3 Rerun the full local e2e suite on the devnet state, to confirm the fixes did not regress `local:deploy`, then
      run `pnpm lint`, the contracts `typecheck`, `test:deploy` and `test:deploy:integration`

## 10. Docs and the deploy-readiness package (prepared, not executed)

- [x] 10.1 `docs/key-ceremony.md`: deployer reuse for upgrade targets, the full leak impact, and inventory rows for
      the immediate-role holders
- [x] 10.2 `specs/CHAIN-ADOPTION.md` and `specs/INFRASTRUCTURE.md` §13.1: use the wizard, describe the bootstrap-EOA
      then handoff flow, and make P-256 informational
- [x] 10.3 `deploy/contracts/README.md`: `v3`, the new provisioning variables, upgrade reconciliation and the
      rehearsal; `specs/PAYMASTER-SPECS.md`: EVM `cancun`; `docs/PAYMASTER-TIMELOCK-RUNBOOK.md` §2: name the
      immediate-role holders step and the handoff pre-flight
- [x] 10.4 Write the testnet and `dev` deployment checklist, ordered, with owners:
      1. create the testnet deployer and its 1Password item;
      2. land the `DEPLOYERS.testnet` PR;
      3. fund the deployer, operator and executor on both chains;
      4. run the rehearsal against the real deployer address on a fork;
      5. run the real deploy on Base Sepolia, then Ethereum Sepolia;
      6. commit the records and publish the contracts package;
      7. apply the `GIANO_CHAINS` and Terraform changes;
      8. bump `infra/versions.json` `dev`;
      9. smoke-test;
      10. retire the legacy paymaster
- [x] 10.5 Draft the `GIANO_CHAINS` entries and the Terraform `paymaster_address` / `factory_address` changes against
      the rehearsal's output, marked as placeholders until the real addresses exist
- [x] 10.6 Record the open decisions the checklist depends on: `dev` reset or migration, rehearsal delays and the
      Safe proposer for testnet, and the immediate-role holders
- [x] 10.7 Changeset for `@appliedblockchain/giano-contracts`
