# Testnet v3 rollout record

Release v3 of Giano's contracts was deployed on Base Sepolia (84532) and Ethereum Sepolia (11155111) between
2026-11-16 and 2026-11-23, and the `dev` environment was moved onto it. This is the public record of what was
deployed, what was decided and what was found. The steps are in [`TESTNET-ROLLOUT.md`](TESTNET-ROLLOUT.md); to
deploy again elsewhere, follow [`docs/FRESH-DEPLOYMENT.md`](../../docs/FRESH-DEPLOYMENT.md).

## Outcome

| Date | Milestone |
|---|---|
| 2026-11-16 | Deployment tooling merged (#279); watcher log span reduced to 200 blocks (#294) |
| 2026-11-17 | Core contracts deployed, provisioned and handed to the timelock on both chains |
| 2026-11-18 | Test ERC-20 deployed on both chains; records published in `@appliedblockchain/giano-contracts` 7.1.0 |
| 2026-11-19 | `dev` cut over to release v3 (#314); its pre-v3 user data cleared |
| 2026-11-23 | Sponsorship rules installed for both tenants; smoke test passed on both chains |

`dev` has since rolled forward with normal deploy PRs; `infra/versions.json` holds its current version.

## Deployed contracts

The same addresses on both chains (CREATE3, testnet canonical deployer). Records:
`packages/contracts/deployments/84532.json` and `11155111.json`.

| Contract | Address |
|---|---|
| Wallet implementation | `0x265dA930A9253fCC09E120B6f89EE8a91BcA9406` |
| Wallet factory | `0xA9d72F088C0Cd0B78db44D4c79E847FddD52F635` |
| Paymaster implementation | `0x3C99Acb0e2AE5C446E5eeab23D6cd7F40e9C5540` |
| Paymaster proxy | `0xb2C7081be89D88f1da020530Ebd5c14b8871615a` |
| GianoTimelock | `0x7Da25D415f9b68422F905C015137Af8D915F8A78` |
| Test ERC-20 (`PrivateERC20`, open mint) | `0x461E0641a3615336b7D2E4C5D71fB2BB88038C93` |
| EntryPoint v0.9 (canonical, not deployed here) | `0x433709009B8330FDa32311DF1C2AFA402eD8D009` |

| Chain | Core contracts (blocks) | Timelock (block) | Test ERC-20 (block) |
|---|---|---|---|
| Base Sepolia | 60059579–60059598 | 60061948 | 60413516 |
| Ethereum Sepolia | 12155749–12155832 | 12155866 | 12161440 |

| Account | Address | Role |
|---|---|---|
| Testnet canonical deployer | `0xBf8e1e80ac0687f2dd0b2909f5a68E3f6d5c41B5` | deploys the core contracts and the test ERC-20 |
| Testnet admin | `0x033178C012FAAB6977FE3b760e5Ca9BBAb4F3030` | timelock proposer and canceller; holds the six immediate roles |
| Sponsorship signer | `0x48bCd7Dd70c6861aF0844F4dBC1dE6Df24048a44` | signs `dev`'s sponsorship authorisations |
| Bundler executor | `0x945BA79715f48D586380604147ae6cD9050b60aC` | submits `dev`'s bundles on both chains |

## Configuration

- **Roles.** The timelock holds `ROLE_ADMIN`, the upgrader, the fee admin and the withdraw-address admin. The
  admin key holds the six immediate roles (signer admin, param admin, pauser, stake admin, tenant admin, fee
  collector). Each role has exactly one holder.
- **Timelock delays.** Minimum 5 minutes; upgrades and role changes 1 hour; tenant withdrawal address
  30 minutes; default fee 20 minutes; tenant fee 10 minutes. Execution is open to anyone.
- **Paymaster.** Stake 0.1 ETH with a 1-day unstake delay. Tenants `example` and `byoui`, 0.02 ETH each on each
  chain, both sponsoring the test ERC-20 (all functions) and wallet management.
- **`dev`.** Its `chains` secret, Terraform variables and reference dApps point at the addresses above; the
  dApps use the test ERC-20 as their default token.

## Decisions

| # | Question | Decision |
|---|---|---|
| D1 | Migrate `dev`'s pre-v3 accounts, or reset? | Reset: clear users, passkeys and sessions at the cut-over; keep tenants, their configuration and the console admins |
| D2 | Timelock proposer | One admin EOA on testnet, no Safe |
| D3 | Holders of the immediate roles | The same admin EOA |
| D4 | Timelock delays | Keep the profile's testnet delays (above) |
| D5 | Tenants and what they sponsor | Both `dev` tenants; a test ERC-20 deployed with `deploy:cli test-token` (#303) and allow-listed |
| D6 | RPCs | Keyed endpoints (they serve `eth_getLogs` over up to 10,000 blocks, so the bundler needs no override) |
| D7 | Testnet ETH | Funded from accounts that belong to the project only |
| D8 | Custody of the testnet canonical deployer key | Its own 1Password item, for the developers who deploy and the tech lead (#296); the vault's membership is still to confirm |
| D9 | Fix the six deploy-tooling review follow-ups (G42) before the first live deploy? | Yes, all six, in #298 |
| N4 | wallet-api and an RPC that caps `eth_getLogs` at 200 blocks | Reduce the watcher's span to 200 now (#294); optimise later |

## Status

| Phase | Status |
|---|---|
| 0–1. Tooling, watcher span | Done (#279, #293, #294) |
| 2–5. Decisions, keys, rehearsal, funding | Done |
| 6–7. Deploy Base Sepolia and Ethereum Sepolia | Done |
| 8. Publish records, release | Done (#304, #309, 7.1.0) |
| 9. Sponsorship rules | Done |
| 10. Cut over `dev` | Done (#311, #314) |
| 11. Smoke test | Done (#328) |
| 12. Retire the legacy deployment | Deferred (G46) |
| 13. Timelocked upgrade rehearsal | Deferred (G46) |
| 14. Close out | Done; the cut-over's backup schema is to be dropped |

## Smoke test evidence (2026-11-23)

`pnpm -F @appliedblockchain/giano-e2e smoke --target <dApp URL>`: a new passkey account and a sponsored mint of
the test ERC-20 on each chain, paid by the paymaster proxy above. The account address is the same on both chains.

| Tenant | Account | Base Sepolia transaction | Ethereum Sepolia transaction |
|---|---|---|---|
| `example` | `0x35236785da2d2F4d25Cd5Bd97Fa6A7075F3aDB7a` | `0x7d2e45c19fb86d95c3addf817479ef4ad76e5c646a16ee2c4d342984321d9f2e` | `0x3a4327cc3694e53eb8d69b40a836842701aa2df461f4b9f5344d8dfa23d5d658` |
| `byoui` | `0xC0171CF4BAD1148DD826459e8f067b8EBAA7E0b3` | `0xccb87e48dd50561147bcd9f91328a364684f508a2daaf9496f682f884e811f95` | `0x01e9c7c2538afdcece0f8d92f0cc8656c5f22faab856d2cbb52c8947b303adc6` |

## Findings

| ID | Finding | Resolution | Status |
|---|---|---|---|
| N4 | The watcher's 9,000-block `eth_getLogs` was refused by Base Sepolia's public RPC (200-block cap), so every tenant read as unfunded | Span reduced to 200 (#294) | Done |
| F1 | viem caches the block number for about 4 s, so a scan "to the head" can stop short | `cacheTime: 0` in the hand-off scan | Done |
| F2 | Biome 2.6.5 formats YAML | Files reformatted | Done |
| F3 | The Aderyn binaries were withdrawn upstream, breaking CI | Aderyn removed (#288) | Done |
| F4 | The SDK's log-read floor (250 blocks) was above Base Sepolia's 200-block cap | Floor 200 (#294) | Done |
| F5 | A fresh wallet-api needs about 2 minutes to replay its look-back at 200 blocks a pass, refusing sponsorship meanwhile | Readiness waits for the watcher lag | Done |
| F6 | The bundler's 2,000-block receipt lookup is refused by Base Sepolia's public RPC | Keyed RPCs (D6) | Done |
| F7 | Console log reads re-narrowed on every window (about 650 relay calls for 45,000 blocks) | Fixed (#294) | Done |
| F8 | wallet-api stores each passkey's wallet address at registration, so pre-v3 users would keep their old addresses | Reset at the cut-over (D1) | Done |
| F9 | `deploy:cli testing` also deploys a paymaster that sponsors anything | Test ERC-20 deployed with `test-token` instead (#303) | Done |
| F10 | A rehearsal clears its logs at start and leaves its compose projects running | Documented workaround | Done |
| F11 | The legacy Ethereum Sepolia paymaster had a different sponsorship signer | The v3 deployment registers the same signer on both chains | Done |
| F12 | `deploy:cli testing` signs with any key named `DEPLOYER_PRIVATE_KEY` | `test-token` refuses a signer other than the canonical deployer (#303) | Done |
| F13 | The tooling refused the test ERC-20 on the served testnets | Allowed on testnets, refused on mainnets (#303) | Done |
| F14 | A deployer funded with exactly its reserve could not resume a stopped deploy | Top-up; fund the reserve plus a margin | Done |
| F15 | A lagging RPC made the deploy stop twice and the hand-off revert three times from stale gas estimates; every rerun resumed | Tooling follow-up | Open (G46) |
| F16 | A new picomatch advisory with no fix failed the dependency audit | Accepted until a fix ships (#305) | Done |
| F17 | `changeset version` left `pnpm-lock.yaml` out of date, failing the version PR | Lockfile regenerated; workflow follow-up | Open (G46) |
| F18 | The paymaster watcher's cache is keyed by chain, so it would keep the legacy paymaster's state | Cleared by the cut-over reset (#311) | Done |
| F19 | `dev`'s previous image had expired from ECR, so the reset could not run before the roll | Roll first, then reset; runbook updated (#326) | Done |
| F20 | A new Go standard-library CVE in the BYO wallet image's esbuild binary failed image builds | Accepted (#317) | Done |
| F21 | The full `terraform apply` ran from a checkout without the deploy PR and was rolled back | Re-applied from `main`; runbook updated (#326) | Done |
| F22 | Base Sepolia makes about 5 blocks a second, so the watcher (200 blocks per 4 s poll) needs over an hour to catch up after a scale-down | Let the span follow the RPC | Open (G46) |
| F23 | Node 26 reads `--env-file` itself, so a repository-relative path fails | Use an absolute path; tooling follow-up | Open (G46) |

## Follow-ups

- **G46:** the open findings above (F15, F17, F22, F23), recovering the legacy paymaster's testnet ETH (Phase 12)
  and the timelocked upgrade rehearsal (Phase 13).
- **G44:** the review follow-ups from #310.
