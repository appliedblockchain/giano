# Paymaster timelock runbook (G9)

Who can change what on `GianoPaymaster`, how long each change waits, and what to do when a key or a
Safe signer is lost or leaked. The decisions are recorded in `specs/PAYMASTER-REQUIREMENTS.md`
(R-68 to R-70); the contract design is in `specs/PAYMASTER-SPECS.md` §4.3.

## 1. The topology

```
Safe (N-of-M)  ──proposes / cancels──▶  GianoTimelock  ──holds──▶  ROLE_ADMIN
                                        (a delay per               UPGRADER_ROLE
                                         function)                 FEE_ADMIN_ROLE
                                                                   WITHDRAW_ADDRESS_ADMIN_ROLE
Operational keys  ──────────────── call directly ─────────────▶  every other role
```

Multi-party control is the Safe's job, not Giano's: Giano deploys the timelock, decides what goes
through it and checks that the deployment matches. Any proposer or role holder can be a Safe.

### Timelocked: queued publicly, executable only after the delay

| Operation | Role | Delay key in the profile |
|---|---|---|
| Upgrade the implementation | `UPGRADER_ROLE` | `upgradeToAndCall` |
| Grant a role | `ROLE_ADMIN` | `grantRole` |
| Revoke a role | `ROLE_ADMIN` | `revokeRole` |
| Timelock renounces a role | `ROLE_ADMIN` | `renounceRole` |
| Change a tenant's withdrawal address | `WITHDRAW_ADDRESS_ADMIN_ROLE` | `setTenantWithdrawAddress` |
| Change the default fee | `FEE_ADMIN_ROLE` | `setDefaultFee` |
| Change a tenant's fee override | `FEE_ADMIN_ROLE` | `setTenantFee` |

### Immediate: sent directly by the role's key

| Operation | Role |
|---|---|
| `addSigner`, `removeSigner` | `SIGNER_ADMIN_ROLE` |
| `setPostOpGasAllowance`, `setPenaltyBps` | `PARAM_ADMIN_ROLE` |
| `pause`, `unpause` | `PAUSER_ROLE` |
| `addStake`, `unlockStake`, `withdrawStake` | `STAKE_ADMIN_ROLE` |
| `registerTenant`, `setTenantEnabled` | `TENANT_ADMIN_ROLE` |
| `withdrawFees` | `FEE_COLLECTOR_ROLE` |

### Delays

Every timelocked operation has its own delay. They are published per environment in
`deploy/chains/<chain>.json` under `timelock.delays` (seconds), and are a promise to tenants:
changing them is a product decision, not an operational one.

- `minDelay` is the floor and the delay of anything not listed (for example adding a proposer).
- The upgrade delay must be long enough for a tenant to withdraw its balance (R-51).
- `grantRole`, `revokeRole` and `renounceRole` must each be at least the longest other delay.
  Granting a timelocked role to a key would let that key skip the role's delay from then on.
  Tooling refuses a policy that breaks this, and `giano-doctor` fails it.
- Changing a delay is itself queued, and waits at least the delay it changes. Shortening the
  upgrade delay from 7 days takes 7 days.

The testnet profiles carry short rehearsal delays (minutes to an hour). **Production delays have
not been set yet.** They need product sign-off before the first mainnet deployment.

## 2. Setting up a chain

After `pnpm contracts:deploy` and `pnpm contracts:provision` (which leave every role on the
provisioning key):

1. Create the proposer Safe on the chain. Add it to the profile under `timelock.proposers`, and
   leave `timelock.executors` empty for open execution (anyone can run a ready operation; nobody
   can run one early) or list the Safe to restrict it.
2. `pnpm contracts:timelock --chain <profile> --env-file <operator-file>` deploys the
   `GianoTimelock` with the profile's delays and saves its address in the profile. It signs with
   the current `ROLE_ADMIN` key (`ROLE_ADMIN_PRIVATE_KEY`, or `DEPLOYER_PRIVATE_KEY` as provisioning
   uses).
3. `pnpm contracts:handoff --chain <profile> --env-file <operator-file>` grants the four timelocked
   roles to the timelock, revokes them from everyone else and renounces the provisioning key's
   `ROLE_ADMIN` last. **Only the timelock can undo this, after the role delay.** To review the calls
   first, or if `ROLE_ADMIN` is held by a Safe, run the plan form and upload the batch to the Safe
   Transaction Builder:
   ```sh
   pnpm --filter @appliedblockchain/giano-contracts deploy:cli handoff \
     --rpc "$RPC_URL" --timelock <timelock> --role-admin <current ROLE_ADMIN> --safe-json handoff.json
   ```
4. `pnpm contracts:doctor --chain <profile>` must pass. With a timelock in the profile it asserts
   that each timelocked role is held by the timelock alone, and that each delay is at least the
   published one (R-70). On a mainnet chain a timelocked role on a key always fails.
5. Commit the profile (with the timelock address) and `deployments/<chainId>.json`.

## 3. Making a timelocked change

1. **Propose.** Build the proposal without hand-encoding calldata:
   - fees, withdrawal addresses and roles: the `giano-paymaster` CLI with `--timelock <address>`
     prints the proposal (operation id, delay, schedule / execute / cancel calldata), and with
     `--safe-json <file>` writes a Safe Transaction Builder batch. The operator console's Timelock
     panel builds the same proposal and lets you download the batch.
   - upgrades: `deploy:cli upgrade --contract paymaster --timelock <address> --safe-json upgrade.json`
     deploys the new implementation under its versioned label and writes the proposal.
2. **Schedule.** The Safe signers review and execute the batch. The timelock checks that the
   delay is at least the operation's own delay and rejects it otherwise.
3. **Announce.** For an upgrade or a fee change, tell the affected tenants: the operation id, what
   it does and its ETA. The queue is public (the `CallScheduled` event), but R-51 requires an
   announcement too.
4. **Wait.** `giano-paymaster timelock pending` and the console list operations with their ETA and
   state.
5. **Execute.** Once ready, any executor sends `execute` (`giano-paymaster timelock execute <id>`,
   the console's Execute button, or the Safe if executors are restricted to it).
6. **Verify.** Run `giano-doctor chain` again after role or delay changes.

To withdraw a proposal while it is pending, a proposer (the Safe) sends the `cancel` calldata the
proposal printed.

### Changing a delay

Propose a call to the timelock itself: `setFunctionDelay(<paymaster>, <selector>, <seconds>)` for
one function, or `updateDelay(<seconds>)` for `minDelay`. Either waits at least the delay being
changed. Then update the profile and re-run `giano-doctor`.

## 4. Role rotation

| What | How | Waits |
|---|---|---|
| Rotate an immediate role's key (signer admin, pauser, …) | Propose `grantRole(role, newKey)` and `revokeRole(role, oldKey)` in one batch | the role delay |
| Rotate the sponsorship signing key (G8) | `addSigner(new)`, switch the service to it, then `removeSigner(old)` | immediate |
| Change the timelock's proposer Safe | Propose, on the timelock itself, `grantRole(PROPOSER_ROLE, newSafe)`, `grantRole(CANCELLER_ROLE, newSafe)`, then revoke both from the old Safe | `minDelay` |
| Replace the timelock | Deploy a new timelock, propose `grantRole` of each timelocked role to it, then propose the old timelock's `renounceRole` of each | the role delay |
| Rotate Safe signers or threshold | In the Safe itself; nothing changes on the paymaster or the timelock | the Safe's own policy |

## 5. Compromise

**A sponsorship signing key leaks.** `removeSigner` immediately (signer admin). It takes effect in
the next block. If the signer admin key is itself unavailable, `pause` stops all new sponsorship at
once while the role is rotated; withdrawals stay open while paused.

**An immediate role's key leaks.** The damage is bounded to that role (R-48: no role can move a
tenant's balance). Contain it with what is immediate:

- signer admin: the attacker can add a signer that authorises sponsorship against tenant balances.
  `pause` at once, remove the signer once the role is back. The role itself is rotated through the
  timelock, so expect to stay paused for the role delay.
- pauser: the attacker can pause, or unpause during an incident. Re-pause and rotate.
- param admin: overhead parameters are bounded on-chain (`penaltyBps ≤ 5000`). Reset them, and
  rotate.
- tenant admin: the attacker can register junk tenants or disable real ones. Re-enable them and
  rotate. It cannot redirect withdrawals; that power is timelocked.
- stake admin: the attacker can unlock the stake, which starts the EntryPoint's unstake delay, and
  then withdraw it to themselves. Re-stake with `addStake` straight away and rotate the role. The
  stake is not tenant money.
- fee collector: the attacker can withdraw accrued treasury, never tenant balances.

Every rotation is a `grantRole` and `revokeRole`, so it waits the role delay. Pausing is the bridge.

**A Safe signer leaks.** If the threshold still holds, rotate the signer in the Safe. Nothing on
the paymaster changes.

**The proposer Safe is compromised (threshold reached).** Every malicious change is still public for
its delay. Watch `CallScheduled` on the timelock; this is why monitoring the queue matters.
- A proposer is also a canceller, so the attacker can cancel legitimate proposals, and legitimate
  signers can cancel the attacker's while they still control the Safe.
- If you cannot cancel: `pause` (immediate) stops new sponsorship. Tell tenants to withdraw before
  the ETA of the hostile operation. Withdrawal is not timelocked and works while paused.
- Then recover control of the proposer role through a second proposer Safe if one was set up, or
  accept that the paymaster must be abandoned once tenants have withdrawn.

Consider a second, independent proposer Safe kept for recovery. It can also cancel a hostile
operation queued by the first.

## 6. Rehearsal on a testnet

Before mainnet, run the full flow on Base Sepolia with a real Safe: set up as in §2, queue an
upgrade (§3), wait the delay, execute, and run `giano-doctor`. The testnet profiles' short delays
exist so this fits in an afternoon.
