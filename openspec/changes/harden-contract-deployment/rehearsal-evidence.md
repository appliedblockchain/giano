# Rehearsal evidence

Results of task groups 1, 3 and 9. Base Sepolia fork, anvil 1.7.1 (`deploy/docker-compose.fork.yml`), branch
`feat/harden-contract-deployment` off `main` at `5d81dd2c`.

## 1. Local baseline (12 November 2026)

| Check | Result |
|---|---|
| e2e stack rebuilt from `main` (`down -v`, `up --build --wait`) | up; sponsorship and tx-mapping provisioners exited 0 |
| Playwright, full suite | 97/98. `platform-console.spec.ts:408` (ending another session) timed out once while a rehearsal ran in parallel; passes alone and in a rerun of its spec file (11/11). Timing flake, not a regression |
| `forge test` (pinned Foundry v1.7.1 image) | 249/249 in 29 suites |
| `test:deploy` | 90/90 |
| `test:deploy:integration` (host anvil 1.7.1) | 3/3 |

## 3. Rehearsal, first pass (before fixes)

`pnpm contracts:rehearse [--release v3] [--platform]`. The fork was taken at the latest block of each run.

| Step | `v2` (committed profile) | `v3` | `v3 --platform` |
|---|---|---|---|
| fork, prepare | ✓ | ✓ | ✓ |
| deploy (wizard, stand-in deployer) | ✓ | ✓ | ✓ |
| provision | ✓ | ✓ | ✓ |
| timelock, handoff | ✓ | ✓ | ✓ |
| upgrade proposed, scheduled, executed through the timelock | ✓ | ✓ | ✓ |
| plan after upgrade | ✗ D2 | ✗ D2 | ✗ D2 |
| provision after upgrade | ✗ D2 | ✗ D2 | ✗ D2 |
| doctor | ✓ (passes on a chain the plan refuses) | ✓ | ✓ |
| platform-up (docker-compose.chain.yml on the fork; wallet-api's boot checks pass) | — | — | ✓ |
| sponsorship rules | — | — | ✗ D2 (same pre-check) |
| browser smoke | — | — | skipped |

### What it confirmed, and what it found

- **D2 confirmed on the real path.** After the timelock executes the upgrade, `contracts:deploy --plan` reports
  "paymaster proxy … points at 0xa965…, not the planned paymaster implementation 0xFC6c…", and every operator
  workflow's pre-check refuses. It happens with `v2` and `v3` alike, so it is independent of the release.
- **D1** does not show in the contract steps: `v2` deploys and verifies cleanly. Its harm is the wallet SDK
  (`signed_eth_call` signs the `v3` hash) and the missing paymaster fixes, which the browser smoke and the code review
  cover, not the deployment steps.
- **D7** does not show on Base Sepolia: the chain has both the Arachnid factory and the daimo verifier, so the
  doctor's stale checks pass there. They still fail on a chain without them.
- **N1 (new). EIP-7702-delegated EOAs pass for contracts.** Before the rehearsal switched to its own keys, it used
  anvil's public accounts. On Base Sepolia, accounts 0 and 4 carry EIP-7702 delegations (code `0xef0100…`), and the
  doctor reported proposer account 4 as "contract account, e.g. a Safe". The mainnet proposer check must reject
  delegation designators. Added to the handoff requirement and to task 8.3.
- **N2 (new). A handed-off chain no longer verifies against its profile.** `verifyCoreState` requires the profile's
  `roleAdmin`, the bootstrap EOA, to hold `ROLE_ADMIN`, which the handoff renounces. It is hidden behind D2's blocker,
  which is checked first. Added as the "handed-off deployment verifies against its profile" requirement and task 5.5.
- **N3 (new, found in the gate run). Sponsorship rules never installed on a public chain.** With D2 fixed, the
  `sponsorship-rules` step reached the wallet-api, which answered 400: "allowlist must list at least one contract when
  sponsorship is enabled". `provision-sponsorship.sh` sent an empty allowlist on any chain without the demo ERC-20,
  assuming wallet management would still be sponsored, but the wallet-api's rules sponsor nothing for an empty
  allowlist. Fixed with `SPONSOR_ALLOWLIST` (task 7.6, "Sponsorship rules name the tenant's contracts on a public
  chain").
- **N4 (new, found in the gate run; decision open). The paymaster watcher cannot run on `sepolia.base.org`.** The
  watcher asks for up to 9,000 blocks per `eth_getLogs` (5,000 on a cold start); the Base Sepolia profile's public
  RPC serves 200 ("eth_getLogs is limited to a 200 range"). The watcher ingested nothing and retried the same range
  every poll, so the ledger read the funded tenant as 0 wei and refused every sponsorship (`sufficient-balance`),
  and the drawdown alert fired falsely. `base-sepolia-rpc.publicnode.com` serves the range, and with it as the fork
  upstream (`--fork-url`) the watcher ingests. Not fixed in this change: the choice between requiring such an RPC
  and making the watcher shrink its span is recorded in `deploy/contracts/TESTNET-ROLLOUT.md` "Decisions needed
  first", and in the PR.
- **N5 (harness). The fork's clock.** The timelocked upgrade warps the fork past the delay (1 hour on Base Sepolia),
  so the fork ran 3,599 s ahead of the wall clock that wallet-api signs `validUntil` from, and the bundler refused
  every sponsored operation with `AA32 paymaster expired or not due`. The rehearsal now resets the fork's clock
  (`evm_setTime`) before the platform comes up. Separately, anvil suggests a fixed 1 gwei priority fee (Base Sepolia:
  0.001 gwei), which put a new wallet's first operation at 0.0026 ETH, over the 0.002 ETH wallet-management cap; the
  rehearsal raises that cap as the e2e stack does. Neither affects a real chain.
- **Harness lessons.** Public RPCs serve only recent state, so the fork takes the latest block, not a pinned one.
  anvil's public keys carry strangers' state on testnets, so the rehearsal derives its own keys.
- CREATE3 placement confirmed: `v2` and `v3` land at the same addresses (wallet implementation `0x7E35…`, factory
  `0x74e2…`, paymaster proxy `0x79b8…` for the stand-in deployer), because the address does not depend on the code.

## 9. Rehearsal gate (after fixes)

12 November 2026. `pnpm contracts:rehearse --platform --fork-url https://base-sepolia-rpc.publicnode.com` on the
committed `base-sepolia` profile (`v3`), forked at block 57888391. `--fork-url` sidesteps N4; without it, the fork
reads history through `sepolia.base.org` and the paymaster watcher fails as described there.

**16/16 steps passed.**

| Step | Result |
|---|---|
| fork, prepare | ✓ |
| deploy (wizard, stand-in deployer `0x3d7C…B349`) | ✓ |
| provision (separate role holders, signer by address) | ✓ |
| timelock, handoff | ✓ |
| upgrade proposed, scheduled, executed through the timelock (1 h delay warped) | ✓ |
| plan after upgrade (D2 fixed) | ✓ |
| keyless verify after upgrade and handoff (D2, N2 fixed) | ✓ |
| provisioning refused after the handoff | ✓ |
| doctor | ✓ |
| clock reset (N5) | ✓ |
| platform-up (`docker-compose.chain.yml` on the fork) | ✓ |
| sponsorship rules (N3 fixed, `SPONSOR_ALLOWLIST`) | ✓ |
| browser smoke (`e2e/rehearsal/smoke.spec.ts`) | ✓ |

Addresses on the fork (stand-in deployer, so not the testnet addresses):

| Contract | Address | Transaction |
|---|---|---|
| Wallet implementation | `0x3Fb76CdA4e3485d04B08cC329f994f51348b1B69` | `0xb8967547e550a8609f5e1506acaf3fb3376cbeddea10e388ce09dde1b01829dd` |
| Factory | `0x59b265B1dF4aC0Ec2489b6F1d242F9059d030e6F` | `0xba193ce8b318244e8aa68c77b3ab5539c9f1e24799238c26d49b45897140626e` |
| Paymaster proxy | `0x8d48fE9401Cbf5D435d56f533356cE31593Da60e` | `0x123ddb05bb2ed240d0ccdaccebc45f713c21ab9115403f1726515c1c51140feb` |
| Paymaster implementation after the upgrade (`giano.paymaster.impl@v3`) | `0x961a7D6d41e1f0c9259Ab1984A44b0b2B0545E87` | `0xe41f488ef7809a753c03e8723a83eba7e149603fa6b84e1308c6e24890ca866c` |
| Timelock | `0x9d3bDC372688482c77216AF09142508fb76AA951` | timelock proposal `0xbfe6a3c14d5c4fa7ca836f935d1ff75ad74ed7235640724c536a492efa06d350` |

Platform smoke: a new passkey wallet `0x088FA082D0E95dd60906a3c5D03F3979B70726c4`. Connecting deploys it in a
sponsored operation, then `#send` is a second one. The paymaster booked both against the tenant: balance
0.05 ETH → 0.049135316994647219 (deploy) → 0.048467772990674411 (send).

| Operation | userOpHash | Transaction | Block |
|---|---|---|---|
| Account deployment at connect | `0x3142978b878dfcf6c2ffeb475594fffd98b40e14e36b0d37e3f4d7301b52ff7a` | `0x2eb254b1ba6a6495ef5ca854983be6653e0f61b40a5844ec12da4ac7d846e74e` | 57888502 |
| `#send` (zero-value self-call) | `0x28749d544740c8fda8fd6342909f6062ea6af54ad1744a5f040d0ae40740b45a` | `0x4da5f6208b773d331b934e8efbcb7c32ca12bece80295b4d39b01d181c32b9f2` | 57888505 |

The smoke spec first assumed the account stays counterfactual until its first transaction; the wallet deploys it at
connect (as `e2e/tests/wallet-management.spec.ts` expects), so the spec now checks both operations.

### Local regression check (task 9.3)

| Check | Result |
|---|---|
| e2e stack rebuilt from the branch (`down -v`, `up --build --wait`) | up; sponsorship and tx-mapping provisioners exited 0 |
| Playwright, full suite | 97/98. `paymaster-admin.spec.ts:177` (the confirmation toast must pass clicks through) fails intermittently: 2 of 3 with `--repeat-each 3`. The branch changes nothing under `services/` or the e2e compose file; the assertion came with `48c547e5` on `main`, and this morning's `main` baseline passed it. Not a regression of this change |
| `test:deploy` | 110/110 |
| `test:deploy:integration` (host anvil 1.7.1) | 4/4 |
| contracts `typecheck`, `pnpm lint` | pass |

A first run on the e2e stack restarted with its volumes kept failed 7 tests: Postgres kept the watcher's cursor
(block 130) while the devnet came back from its baked state (head 120), so the watcher ingested nothing. Starting
from `down -v`, as the baseline did, clears it.
