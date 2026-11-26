# Tenant offboarding runbook (G11)

How a platform admin removes a tenant from a Giano deployment: the order of the steps, what each
one changes, what is kept, and what the tenant's users keep. The lifecycle itself is specified in
[`specs/PLATFORM-ADMIN-SPECS.md`](../specs/PLATFORM-ADMIN-SPECS.md) §5 and in the OpenSpec specs
`tenant-lifecycle` and `tenant-chain-drift`. For an incident (a compromised tenant, abuse), suspend
first and read the rest later: suspension is immediate and reversible.

## 1. What cannot be undone or removed

- **A tenant cannot be de-registered on chain.** `GianoPaymaster` has `registerTenant` and
  `setTenantEnabled`, and nothing that removes a record. The tenant's id stays on every paymaster's
  roster, disabled, for good.
- **Delete is a tombstone.** The `tenants` row stays with `status = 'deleted'`. Its slug, id, wallet
  origin and RP ID can never be given to another tenant, because the id keys its paymaster records
  and the RP ID is what its users' passkeys are bound to.
- **Users' wallets are not Giano's or the tenant's.** They are self-custodial smart accounts owned by
  the users' keys. Nothing in this runbook touches them (§4).

## 2. The procedure

Do the steps in this order. Each one names who does it and how to check it.

| # | Step | Who | How | Check |
| --- | --- | --- | --- | --- |
| 0 | **Notice to users.** Agree a date with the tenant. Until then the tenant stays active, so its users can still sign in and move funds or add another owner (§4). The tenant may switch its sponsorship off first (`PUT /v1/admin/sponsorship` with `enabled: false`). | Tenant | Its own channels | Agreed date passed |
| 1 | **Read the tenant's position.** Note its balance, deficit and withdrawal address on every chain, and give them to the tenant. After step 2 its admin keys stop working, so it can no longer read them through `/v1/admin/sponsorship/balance`. | Platform admin | Console: tenant page, *On chain* card for each chain | Figures recorded |
| 2 | **Suspend.** The tenant stops resolving on the next request on every replica: ceremonies, relay, sponsorship, RPC, `/.well-known/webauthn`, admin keys and user sessions all answer as for an unknown tenant. Nothing is deleted, and resume restores it. | Platform admin | Console *Suspend* with a reason, or `POST /v1/platform/tenants/:slug/suspend` `{ reason }` | `tenant_history` has a `suspend` entry with your session |
| 3 | **Disable on every chain where it is registered.** Closes the window in which an authorisation signed before the suspension is still valid on chain (up to `SPONSORSHIP_VALIDITY_SECONDS`). | Platform admin holding `TENANT_ADMIN_ROLE` | Console: the step offered after *Suspend*, `setTenantEnabled(id, false)` per chain. Not timelocked. | Drift shows no `enabled-state` entry for the tenant |
| 4 | **The tenant withdraws its balance.** Only its withdrawal address can call `withdrawTenant(id, amount, to)`, and disabled tenants can still withdraw. A deficit (gas the pooled deposit already paid for it) must be paid with `depositFor(id)` first: delete refuses while one is outstanding. | Tenant | Its withdrawal address, on chain | Ledger balance and deficit are 0 on every chain |
| 5 | **Wait for open reservations to expire**, and for the watcher to sync past the withdrawal. | Platform admin | Console Health: ledger lag below `TENANT_DELETE_MAX_LEDGER_LAG_BLOCKS` | `GET /v1/platform/drift` shows nothing for the tenant |
| 6 | **Delete.** Refused unless the tenant is suspended, holds no balance or deficit and no open reservation on any chain, and every sponsoring chain's ledger is current. | Platform admin | Console *Delete* (type the slug), or `DELETE /v1/platform/tenants/:slug` | `204`; the tenant is listed only under `?status=deleted` |
| 7 | **Infrastructure.** Stop serving the tenant's wallet origin and remove its DNS and certificates, if Giano hosted them. | DevOps | Terraform | — |

A tenant that has abandoned its balance cannot withdraw it. The recovery path is the timelocked
`setTenantWithdrawAddress` by `WITHDRAW_ADDRESS_ADMIN_ROLE`, then a withdrawal by the new address
(`specs/PLATFORM-ADMIN-SPECS.md` §5.3, [`PAYMASTER-TIMELOCK-RUNBOOK.md`](./PAYMASTER-TIMELOCK-RUNBOOK.md)).
It is a public, queued proposal, never an API action.

## 3. What delete keeps and removes

Delete runs in one transaction. Nothing is erased beyond the rows marked *removed*.

| Data | On delete | Why |
| --- | --- | --- |
| `tenants` row | **kept**, `status = 'deleted'` | Tombstone: the id, slug, wallet origin and RP ID stay claimed |
| `tenant_admin_keys` | **removed** (only hashes were ever stored) | The keys must stop working for good; the history records which were removed |
| `sessions` of the tenant's users | **removed** | Nothing may act as the tenant |
| `challenges`, `pending_additions` | **removed** | Open ceremonies and passkey hand-offs end |
| `users` (external user id) | kept | Records we keep; see §5 |
| `credentials` (credential id, public key, wallet address, name) | kept | Public keys only, no secret. Needed to attribute past operations |
| `userop_log`, `wallet_management_log` | kept | Operation records |
| `sponsorship_decisions`, `sponsorship_settlements`, `sponsorship_reservations` | kept | The tenant's billing record |
| `paymaster_tenants` (ledger) | kept, at zero | Rebuilt from chain events; the watcher keeps it current |
| `tenant_sponsorship` and its history, `tenant_tx_mappings` and history, `ror_origins` | kept | Configuration history; inert once the tenant no longer resolves |
| `tenant_history` | kept, with the `delete` entry | The audit trail: who did what, from which platform admin session |
| Application logs (CloudWatch, and Datadog where it is enabled) | expire with each sink's retention: CloudWatch `log_retention_in_days` (7 days on dev and staging, 30 on production), Datadog the account's | Not tenant-scoped; they carry the tenant's slug and request details |
| On-chain paymaster record | stays, disabled, zero balance | Cannot be removed (§1) |

## 4. What the tenant's users keep

- **Their wallet and everything in it, on every chain.** The wallet is a smart account owned by the
  user's passkey (and any other owner they added). Neither Giano nor the tenant can move its funds
  or change its owners.
- **Their passkey still signs for the wallet.** Signatures are checked on chain by the wallet
  contract, not by wallet-api.

What they lose:

- wallet-api's ceremonies, sessions, relay and sponsorship for that tenant, from step 2. Fees are
  no longer sponsored.
- **In practice, the passkey itself, once the wallet origin is gone.** A passkey is bound to its RP
  ID, the tenant's wallet domain. Once nothing serves a wallet on that domain (step 7), the browser
  will not use the passkey anywhere else, and no other Giano tenant can take that RP ID. The wallet
  still exists, but nothing can sign for it with that passkey.

So the notice period (step 0) matters: before it ends, users should move their funds out, or add an
owner they control outside the tenant's wallet (for example an externally owned address, through
the wallet's `addOwnerAddress`). An owner added that way can keep using the wallet with any
ERC-4337 bundler and pay its own gas.

## 5. Open decisions

- **Erasure.** Today delete keeps the users, credentials and logs listed in §3 indefinitely, and
  nothing erases them on request. Whether a deleted tenant's user data must be erased, and after how
  long, is a retention policy decision for the tech lead and legal. Database retention is ticket
  G34.
- **The notice period.** Its length, and whether Giano or the tenant tells the users, is part of the
  tenant's contract, not of this runbook.
- **Enforcing the on-chain disable.** Suspend is a database change. The on-chain disable is offered
  by the console, and drift reports a suspended or deleted tenant still enabled on chain, but
  nothing requires it. wallet-api holds no `TENANT_ADMIN_ROLE` key, so it cannot do it itself.
- **Alerting.** Drift and tenants waiting for registration are metrics
  (`giano_paymaster_drifted_tenants`, `giano_paymaster_unregistered_tenants`) and a `giano-doctor`
  check, but nothing pages on them until Datadog scrapes wallet-api's `/metrics`.
