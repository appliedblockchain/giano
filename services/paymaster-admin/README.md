# Giano paymaster admin

An operator's console for a Giano sponsorship paymaster: its tenants, treasury, stake, roles,
timelock and settled sponsorships, read from the chain, and, where the deployment enables it,
wallet-api's tenant registry and platform admins beside them.

Everything about the paymaster is read straight from the chain over JSON-RPC. The console keeps no
database and caches nothing it shows as a figure: an operational view whose numbers come from a
cache can be wrong in the one situation where being wrong matters most.

Who may read is answered by where the console is deployed: a hosted console reads only for a
signed-in platform admin, through wallet-api; a standalone one must sit behind your own access
control (see [Access](#access)).

```bash
pnpm demo:admin            # from the repo root → http://localhost:4402
```

## The tabs

One tab bar, each tab a page with its own URL (`/`, `/tenants`, `/tenants/<slug>`, `/paymaster`,
`/roles`, `/timelock`, `/activity`, `/health`, `/admins`), so reloading, a new browser tab and Back
all land where they point. The deployment is chosen in the header, not in the URL.

- **Overview** — first what needs an operator, each with a link to where it is fixed: the
  invariant breached, the paymaster paused or unstaked, tenants in deficit, unfunded, unregistered
  or disagreeing with the registry, ready timelock operations. Then the deposit, tenant balances,
  treasury and stake, solvency with its slack, the configuration with the implementation, and what
  is queued in the timelock.
- **Tenants** — one list: wallet-api's registry joined by tenant id to the selected chain's
  paymaster roster, with lifecycle and on-chain state, balance, deficit, fee, users, queued changes
  and the next step. Search, a state filter, totals. Without the platform API it is the roster by id.
- **A tenant** (`/tenants/<slug>`) — its state on this chain with register, fund, enable or disable,
  fee override and withdrawal address; wallet-api's ledger compared with the chain; the tenant on
  every other configured chain; its recent sponsorships; the registry record and admin keys (never
  key material); its history with each edit's before and after, and its admin events on the chain
  (registration, funding, withdrawals, enabled state, fee, withdrawal address); and the lifecycle
  actions its state allows.
- **Paymaster** — one card per setting, each naming the role it needs: pause, signing keys,
  pricing, operational parameters, treasury (with *Max*), stake (add, unlock, withdraw, with the
  unlock date) and upgrade (the implementation from the ERC-1967 slot).
- **Roles** — every role, timelocked or immediate and its delay, its holders by name, what it may
  and may **not** do, queued changes with *Execute*; grant, revoke, renounce and rotate.
  `DEFAULT_ADMIN_ROLE` is shown because it should be held by nobody.
- **Timelock** — with `timelockAddress` configured: who proposes, cancels and executes, what your
  wallet may do, its operations with *Execute* and *Cancel*, its delays and its own roles, each with
  a proposal to change them.
- **Activity** — settled sponsorships with time, tenant, account, outcome, gas, fee and overhead,
  filters and totals, *Look further back* with no row cap, and *Export CSV*. Below them, the admin
  events: who changed a role, a fee, a parameter, a signing key, the pause state, the code or a
  tenant, and, with `timelockAddress`, what was scheduled, executed or cancelled on the timelock and
  its own delays and roles. Filtered by kind, read a window at a time like the settlements.
- **Health** — the checks `giano-doctor` runs, at the same thresholds, grouped as Funds, Keys and
  roles, and Registry and chain, each saying what to do and where; with the platform API, also that
  every on-chain tenant has a registry row and that wallet-api's ledger matches the chain. Keys and
  roles also says whether the paymaster's implementation is a contracts release and, with
  `timelockAddress`, whether the timelock alone holds the four timelocked roles and whether any
  delay is below `timelockDelays`. Without a timelock, one warning says none is configured. With
  the platform API, a Chains section shows what wallet-api sees of each chain it serves: whether it
  serves it, the node's head and its age, whether the bundler lists the configured EntryPoint, the
  ledger watcher's lag, and the sponsorship signer. The head-age and lag thresholds are in
  `src/lib/health.ts`.
- **Admins** — with the platform API: who may sign in, when each last did and how many sessions
  they have open, the change history, *Add admin* and *Remove*; and your own sessions from the last
  30 days, with *End* on any open one but the one you are using.

## The write rules

Every control that sends a transaction is shown whether or not your wallet may use it. One that it
may not is disabled and says why — the role it needs, or that a wallet must be connected — because
hiding a control just produces a support ticket. A write that is destructive (pause, revoke, remove
a signer, disable a tenant, withdraw, unlock or withdraw the stake, upgrade, execute, cancel) asks
first and says what it does. Every address and amount field checks its value as you type, says
what is wrong under the field, and keeps its button disabled until it is right.

### Timelocked actions

Fees, withdrawal addresses, role changes and upgrades are timelocked (G9): on a handed-off
deployment only the timelock holds their roles, and its proposer is a Safe. So the same control
resolves three ways:

- **Send** where your wallet holds the role — a devnet, where one key holds everything;
- **Propose**, in the timelock's purple with a clock, where it does not and a timelock is
  configured. This opens the proposal instead of a transaction that would revert;
- disabled, naming the role, where there is neither.

The proposal dialog takes one or more calls that execute together (a role rotation is a grant and a
revoke in one operation), a salt, a delay no shorter than the timelock requires and a predecessor.
It shows the operation id, when it could execute, and the schedule, execute and cancel calldata, and
saves the Safe Transaction Builder batch for each step. A wallet holding the timelock's
`PROPOSER_ROLE` can schedule it from there. Building a proposal needs no wallet and no role.

A change that is queued is marked where it will land — a tenant's fee, a role, the implementation —
with when it is ready and a link to the operation.

## Connecting a wallet

In a standalone console reads need no wallet. Where the platform API is configured, reading needs a
platform admin sign-in, and the sign-in uses the wallet. Either way, the wallet enables the writes
its account's roles allow.

The console never sees a key. It asks an injected EIP-1193 wallet to sign, which is the only shape
that works when the role holders are hardware wallets and timelocks. Connecting asks the wallet to
move to the deployment's chain, and adds it where the wallet does not know it.

Withdrawing a tenant's balance is deliberately absent. Only that tenant's own registered withdrawal
address can do it, and no role on the paymaster can — including every role at once.

## Signing in

With the platform API (`GIANO_WALLET_API_UPSTREAM`), the console shows a sign-in page in place of
whatever path was opened, and that path once signed in. The connected wallet signs a message
wallet-api wrote, naming this console's domain; the address must be one of wallet-api's platform
admins (its `platform_admins` table). The session lives in the page's memory only: a reload, an
account or network change, a deployment switch, sign-out, disconnecting the wallet, or its expiry
(30 minutes) ends it. Two minutes before it ends, a card offers *Stay signed in*: a fresh signature
that replaces the session in place, keeping whatever you were typing.

The first platform admins come from wallet-api's init step, per environment
(`services/wallet-api/src/environments.ts`), and only into an empty list. After that the Admins tab
manages them: an added admin can sign in at once, and removing one ends their sessions at once.
Nobody can remove themselves or the last admin.

Tenants can be created, edited, suspended and deleted at runtime, with no redeploy
([`specs/PLATFORM-ADMIN-SPECS.md`](../../specs/PLATFORM-ADMIN-SPECS.md)). On-chain follow-ups —
registering, disabling on suspend, enabling on resume — are offered after the API action, never
instead of it, and never undo it.

## Configuration

Runtime, from `/config.json`, fetched before the first render — not build-time `VITE_` variables.
One published image serves every deployment; an image baked to a single chain is how a production
console ends up pointed at a devnet.

The file declares the deployments the console may administer. That list is the whole of what it can
reach: an operator picks between environments someone configured deliberately, and cannot point the
console at an arbitrary chain by typing into it.

```json
{
  "deployments": [
    { "name": "base sepolia", "chainId": 84532, "rpcUrl": "https://…", "sponsorshipPaymaster": "0x…", "refreshSeconds": 30 },
    { "name": "local devnet", "chainId": 31337, "rpcUrl": "http://localhost:8545", "sponsorshipPaymaster": "0x…", "refreshSeconds": 10 }
  ]
}
```

| Key | |
| --- | --- |
| `name` | how an operator tells this environment apart; shown in the header |
| `chainId` | required |
| `rpcUrl` | required. With `GIANO_WALLET_API_UPSTREAM` set it is replaced by wallet-api's platform read relay, `/api/v1/platform/rpc/<chainId>`; otherwise proxied through this origin unless `GIANO_RPC_PROXY=false` |
| `sponsorshipPaymaster` | the proxy. See the caveat below — set it |
| `timelockAddress` | optional: the paymaster's GianoTimelock. Enables the Timelock tab's reads and the proposal flow, and Health's timelock checks |
| `timelockDelays` | optional: the delays the chain publishes, in seconds, as its profile's `timelock.delays` (`deploy/chains/*.json`): `{ "minDelay": 300, "upgradeToAndCall": 3600, … }`. Health fails a delay below its value, as `giano-doctor` does. Unset, Health says the delays were not compared |
| `refreshSeconds` | poll interval; `0` disables polling |
| `nativeCurrency` | optional, from the chain descriptor: `{ "symbol": "POL", "decimals": 18 }`. Amounts are shown and typed in it. Absent means ETH |
| `explorerUrl` | optional: e.g. `https://sepolia.basescan.org`. Transaction hashes and addresses link to `<explorerUrl>/tx/<hash>` and `/address/<address>`. Must be `https:`, or `http:` on localhost. Unset, they are shown in full and copyable |
| `addresses` | optional: names for addresses the chain cannot name, `{ "0x…": { "label": "Safe", "kind": "safe" } }`. Shown wherever the address appears; a `safe` also shows its threshold, *Safe · 3 of 5*. A timelock cannot list its role holders, so this is how the console knows which Safe proposes |

`name`, `chainId`, `rpcUrl` and `sponsorshipPaymaster` are the shared fields of the backend chain
document (`packages/contracts/chains.ts`) that wallet-api and giano-bundler read as `GIANO_CHAINS`.
So a deployment running them can hand `GIANO_DEPLOYMENTS` that same value and have one authored
chain list instead of three.

In that document the console's own settings sit in its section: `paymasterAdmin.walletRpcUrl`,
`paymasterAdmin.timelockAddress`, `paymasterAdmin.timelockDelays`, `paymasterAdmin.explorerUrl`, `paymasterAdmin.addresses` and
`paymasterAdmin.refreshSeconds`. A standalone list may spell
them flat, as in the table above.

The container keeps the keys above and drops everything else rather than publishing it in a file
served to the browser: `entryPoint`, the `walletApi` and `bundler` sections, and anything added
later.

With more than one entry the header shows a **picker**; with one it shows the label as a badge. The
choice is remembered in `localStorage`, keyed on chain and address rather than on the label, so
rewording a label never silently moves the selection to another environment.

Switching deployments **drops the connected wallet**. It was bound to the old chain and its roles
were read from the old paymaster, so keeping it would offer actions the account may not hold on the
deployment now on screen. Reconnecting is one click.

> **`sponsorshipPaymaster` is optional in the schema but required in practice.** Leaving it out asks the
> SDK to resolve the address from the contracts registry, and no chain in `packages/contracts/addresses.ts`
> currently declares a `sponsorshipPaymaster`. Omit it and the console fails to start, loudly.

`public/config.json` is the dev copy. The container renders `docker/config.json.template` from
either `GIANO_DEPLOYMENTS` (a JSON array — the general form) or the single-deployment shorthand
`GIANO_CHAIN_ID` / `GIANO_RPC_URL` / `GIANO_PAYMASTER_ADDRESS` / `GIANO_TIMELOCK_ADDRESS` /
`GIANO_EXPLORER_URL` / `GIANO_ENVIRONMENT_LABEL` / `GIANO_REFRESH_SECONDS`. `addresses` needs
`GIANO_DEPLOYMENTS`.

`GIANO_WALLET_API_UPSTREAM` (e.g. `http://wallet-api:8080`) turns on the platform API (the registry, Admins and sign-in) and gates
every read: the container proxies `/api/*` to wallet-api on its own origin, drops the browser's
`Origin` header (wallet-api's platform routes refuse any request carrying one), re-resolves the
upstream per request through the nameserver in `/etc/resolv.conf`, points each deployment's reads at
wallet-api's platform read relay, and renders `"platformApi": true`. Unset, none of that exists and
the console is exactly the chain view. This console's host must be the sign-in domain
wallet-api's environment names (`siweDomain` in `services/wallet-api/src/environments.ts`, chosen by
its `GIANO_ENVIRONMENT`); changing it is a wallet-api release.

## Access

The console's design gives it nothing to protect on its own — every write is signed by the
operator's wallet and authorised on chain by the paymaster's roles. What needs protecting is what it
reads with: `rpcUrl` is usually a keyed provider endpoint, and its quota is the one wallet-api's
production traffic depends on. Where that key lives, and who may spend it, depends on the mode.

### Hosted: with `GIANO_WALLET_API_UPSTREAM`

The console reads the chain only through wallet-api's platform read relay,
`/api/v1/platform/rpc/<chainId>`, and only with a platform admin session. The relay forwards the same
read-only methods as wallet-api's tenant relay, refuses bodies over 16 KiB, bounds `eth_getLogs` to
`PLATFORM_RPC_MAX_LOG_BLOCKS`, and rate-limits each session (`PLATFORM_RPC_RATE_LIMIT_PER_MINUTE`).
The keyed URL is held by wallet-api alone: this container renders no `/rpc/*` location, whatever
`GIANO_RPC_PROXY` says, and its nginx configuration never contains the URL.

So an anonymous visitor gets the sign-in view and nothing else: no roster, no balances, and no route
to the RPC quota. The page itself — `index.html`, `/assets/*` and `/config.json` — is still public,
on purpose: the bundle is built from this public repository, and `/config.json` names only chains and
paymaster addresses, which the chain publishes anyway. Hiding the page as well takes access control
in front of the whole host (an identity-aware proxy or a load balancer's OIDC), which the console
needs no change to sit behind.

Reading needs a platform admin, which is a row in wallet-api's `platform_admins` table. Holding a role
on the paymaster is not enough.

When the wallet is asked to add a network, it is offered `walletRpcUrl` if set, else `rpcUrl` — which
here is a path that answers only with a session, so no wallet can use it. Set `walletRpcUrl` (in the
chain document, `paymasterAdmin.walletRpcUrl`) to an address you are happy to publish.

### Standalone: without `GIANO_WALLET_API_UPSTREAM`

`rpcUrl` is dialled by the SPA, so a keyed endpoint written into `config.json` would be readable by
everyone who can open the console. So the container proxies every absolute `rpcUrl` through its own
origin: one nginx location per chain, `/rpc/<chainId>`, with the keyed URL server-side and
`/rpc/<chainId>` in the file. `connect-src` is derived from the result, and collapses to `'self'`.

That hides the key, not its quota: nginx cannot read a JSON-RPC body, so **the proxy forwards any
method the provider sells to whoever can reach it.** It is bounded — bodies over 16 KiB are refused
with 413, and every client together is held to `GIANO_RPC_PROXY_RATE` (default `20r/s`, burst twice
that; `600r/m` style also accepted), the excess refused with 429 — but it has no method allowlist and
no notion of who is asking. **A standalone console must sit behind your own SSO, VPN or IP
allowlist.** Anyone who can reach it spends your provider quota.

`GIANO_RPC_PROXY=false` opts out of the proxy, for a node that must be dialled directly or an
upstream nginx cannot reach from where it runs — and then the URL, key and all, is what every visitor
receives. A relative `rpcUrl` is already same-origin and passes through either way.

## What is a view call, and what is a window

Almost everything on screen is an `eth_call` — the roster, balances, deficits, fees, solvency,
stake, roles, health. Each reads a bounded amount of contract state, so it costs the same on a
chain's first day as on its ten-thousandth, and none of it needs a backend.

Two things are not stored on chain and so cannot be view calls: a tenant's **slug**, which
`TenantRegistered` emits and the contract deliberately does not keep, and the **sponsorship
history**, which exists only as `Sponsored` events. Hosted RPCs cap the span a single `eth_getLogs`
may cover — Base Sepolia refuses anything over 10,000 blocks — so reading either from the start of a
deployment is hundreds of requests, growing by about five a day.

The console answers the two differently:

- **Activity** reads one window ending at the head and says which blocks those are. *Look
  further back* reads the preceding window and adds to the table; each refresh reads only the new
  blocks. A settlement record exists nowhere else, so a window is the affordable version of a read
  that has no substitute. The admin events, and a tenant page's events, are read the same way. The
  Timelock tab's operations are too, going back far enough to cover its longest delay.
- **Tenants** take their slug from wallet-api's registry, matched on the tenant id, which is the
  same value as the contract's id. Without the platform API they are listed by id: the roster itself
  is entirely view calls, complete and exact.

Registering a tenant still **writes** a slug, because that event is what lets an auditor reconcile
the on-chain record against the backend's tenant table. To read one back without the registry, use
`giano-paymaster tenant <id>` — it pages backwards with the tenant id as an indexed filter — or a
block explorer.

INFRASTRUCTURE §14.6 has the reasoning and the numbers.

## Addresses

Addresses and other on-chain identifiers are **never abbreviated**, and **clicking one copies it**.
An operator checking that a role holder is the timelock is comparing the whole value, and
`0x1234…5678` hides exactly the middle that distinguishes two addresses from the same deployer.

## In the e2e stack

`deploy/docker-compose.e2e.yml` publishes it on 8083, and portless serves it as
**http://paymaster.localhost**. Open it beside http://app.localhost: a sponsored send from the
sample dApp shows up as a falling tenant balance and a new row under **Activity**.

It waits for the sponsorship provisioner, so it shows a provisioned deployment rather than an empty
roster that looks like a bug.

It runs in hosted mode (`GIANO_WALLET_API_UPSTREAM` is set), so it opens on the sign-in view: anvil's
account 0 (`0xf39F…2266`), the devnet's all-roles account, is bootstrapped as platform admin
`admin-console` for the `e2e` environment. Import that key into a browser wallet and sign in.

## Built on

`@appliedblockchain/giano-paymaster-sdk` — every read and write here is one of its calls, including
the health checks, which it evaluates locally from the overview already on screen.
