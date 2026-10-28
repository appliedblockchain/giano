# Giano paymaster admin

An operator's view of a Giano sponsorship paymaster: tenant balances, treasury, roles, health and
settled sponsorships — all read straight from the chain.

The Paymaster area has no backend of its own. It reads the chain over JSON-RPC and nothing else, so
it keeps no database and cannot show you anything the chain does not already say. That is
deliberate: an operational view whose numbers come from a cache can be wrong in the one situation
where being wrong matters most.

Who may read is a separate question, answered by where the console is deployed: a hosted console
reads only for a signed-in platform admin, through wallet-api; a standalone one must sit behind
your own access control (see [Access](#access)).

Where the deployment enables it, a **Platform** area sits beside it: wallet-api's tenant registry
and the platform admin list, for Giano's own platform admins (see [Platform area](#platform-area)).

```bash
pnpm demo:admin            # from the repo root → http://localhost:4402
```

## What it shows

- **Overview** — the solvency invariant (`Σ tenant balances + treasury ≤ deposit`), deposit, stake
  and pricing. A breach is rendered as an insolvency, not a warning.
- **Tenants** — the whole roster with balances, deficits and effective fees, enumerated on-chain.
- **Roles** — who holds what, and what each role may and may **not** do. `DEFAULT_ADMIN_ROLE` is
  shown precisely because it should be empty.
  Each role is marked **timelocked** or **immediate**.
- **Settings** — signing keys, fees, parameters, stake, treasury, pause.
- **Timelock** — with `timelockAddress` configured: the timelock's minimum delay and each timelocked
  function's own delay, whether it holds the timelocked roles yet, and its operations (waiting,
  ready, done, cancelled) with their ETA, read from its logs. A proposal builder for every
  timelocked action. Where executors are open, **Execute** sends a ready operation from the
  connected wallet; otherwise it saves the Safe execute batch.
- **History** — settled sponsorships, with gas, fee and overhead separately.
- **Health** — the checks `giano-doctor` runs, at the same thresholds.

### Timelocked actions

Fees, withdrawal addresses, role changes and upgrades are timelocked (G9): on a handed-off
deployment only the timelock holds their roles, and its proposer is a Safe. So where the connected
wallet holds the role — a devnet, where one key holds everything — the console sends them directly as
before; where it does not and a timelock is configured, the same control says **Propose** and opens
the proposal instead of a transaction that would revert. A proposal shows the operation id, the
delay read from the timelock, when it would be ready, and the schedule / execute / cancel calldata
(click to copy), and saves the Safe Transaction Builder batch. Nothing is sent: building a proposal
needs no wallet and no role.

## Connecting a wallet

In a standalone console reads need no wallet. Where the platform API is configured, reading needs a
platform admin sign-in, and the sign-in uses the wallet. Either way, the wallet enables the actions
the connected account's roles allow;
everything else stays visible but disabled, with the role it would need named underneath — hiding a
control just produces a support ticket.

The console never sees a key. It asks an injected EIP-1193 wallet to sign, which is the only shape
that works when the role holders are hardware wallets and timelocks. It checks the wallet's chain
rather than silently switching it: quietly moving a hardware wallet to another network is a good
way to sign a treasury withdrawal against the wrong deployment.

Withdrawing a tenant's balance is deliberately absent. Only that tenant's own registered withdrawal
address can do it, and no role on the paymaster can — including every role at once.

## Platform area

Tenants can be created, edited, suspended and deleted at runtime, with no redeploy
([`specs/PLATFORM-ADMIN-SPECS.md`](../../specs/PLATFORM-ADMIN-SPECS.md)). The Platform area is
where Giano's platform admins do it. A header switch moves between **Paymaster** and **Platform**; the
switch only exists when the container is given `GIANO_WALLET_API_UPSTREAM`.

- **Sign in with wallet.** The connected wallet signs a message wallet-api wrote, naming this
  console's domain. The address must be one of wallet-api's platform admins (its `platform_admins` table). The session lives in
  the page's memory only: a reload, an account or network change, a deployment switch, sign-out or
  its expiry (30 minutes) ends it. It is the same session the Paymaster area reads with, so the
  sign-in view shows in both areas and one sign-in serves both.
- **Tenants.** The registry, with each tenant's status and —
  matched on tenant id — its state on the selected paymaster: *registered · enabled*, *registered ·
  disabled* or *not registered*. Roster entries with no registry row are listed on their own.
- **A tenant.** Fields, admin keys (never key material), usage, ledger and history, and the actions
  its state allows: create (keys shown once, then an optional *Register on-chain*), edit,
  suspend (then an optional on-chain disable), resume, delete (type the slug), issue and revoke keys.
- **Admins.** Who can sign in here: each platform admin's id, address, who added them and when; *Add
  admin* (they can sign in at once); *Remove* (their sessions end on their next request); and the
  history of every change. There is no Remove button on your own row, or when only one platform admin
  is left — wallet-api refuses both anyway. The first platform admins come from wallet-api's init step, per
  environment (`services/wallet-api/src/environments.ts`), and only into an empty list.

On-chain follow-ups need `TENANT_ADMIN_ROLE` on the paymaster and are always optional: the API action
has already happened when they are offered.

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
| `timelockAddress` | optional: the paymaster's GianoTimelock. Enables the Timelock tab's reads and the proposal flow |
| `refreshSeconds` | poll interval; `0` disables polling |

`name`, `chainId`, `rpcUrl` and `sponsorshipPaymaster` are the shared fields of the backend chain
document (`packages/contracts/chains.ts`) that wallet-api and giano-bundler read as `GIANO_CHAINS`.
So a deployment running them can hand `GIANO_DEPLOYMENTS` that same value and have one authored
chain list instead of three.

In that document the console's own settings sit in its section: `paymasterAdmin.walletRpcUrl`,
`paymasterAdmin.timelockAddress` and `paymasterAdmin.refreshSeconds`. A standalone list may spell
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
`GIANO_ENVIRONMENT_LABEL` / `GIANO_REFRESH_SECONDS`.

`GIANO_WALLET_API_UPSTREAM` (e.g. `http://wallet-api:8080`) turns on the Platform area and gates
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

- **Sponsorships** reads one window ending at the head and says which blocks those are. *Look
  further back* reads the preceding window and adds to the table. A settlement record exists
  nowhere else, so a window is the affordable version of a read that has no substitute.
- **Tenants** shows no slug at all — a tenant is identified by the id the contract uses, which is
  the same value as its `tenants.id` UUID and which every view call already carries. The panel is
  therefore entirely view calls: complete, exact, and the same cost on a chain's first day as on its
  ten-thousandth.

Registering a tenant still **writes** a slug, because that event is what lets an auditor reconcile
the on-chain record against the backend's tenant table. To read one back, use
`giano-paymaster tenant <id>` — it pages backwards with the tenant id as an indexed filter, which a
console refreshing every fifteen seconds cannot afford to do — or a block explorer.

INFRASTRUCTURE §14.6 has the reasoning and the numbers.

## Addresses

Addresses and other on-chain identifiers are **never abbreviated**, and **clicking one copies it**.
An operator checking that a role holder is the timelock is comparing the whole value, and
`0x1234…5678` hides exactly the middle that distinguishes two addresses from the same deployer.

## In the e2e stack

`deploy/docker-compose.e2e.yml` publishes it on 8083, and portless serves it as
**http://paymaster.localhost**. Open it beside http://app.localhost: a sponsored send from the
sample dApp shows up as a falling tenant balance and a new row under **History**.

It waits for the sponsorship provisioner, so it shows a provisioned deployment rather than an empty
roster that looks like a bug.

It runs in hosted mode (`GIANO_WALLET_API_UPSTREAM` is set), so it opens on the sign-in view: anvil's
account 0 (`0xf39F…2266`), the devnet's all-roles account, is bootstrapped as platform admin
`admin-console` for the `e2e` environment. Import that key into a browser wallet and sign in.

## Built on

`@appliedblockchain/giano-paymaster-sdk` — every read and write here is one of its calls, including
the health checks, which it evaluates locally from the overview already on screen.
