# Giano E2E — the two-tenant demo, and how it is addressed

This package is both the end-to-end test suite and the demo people click through. It runs two
tenants against one shared backend, over four browser origins:

| Origin | Tenant | Served by |
| --- | --- | --- |
| http://app.localhost | `stock` | dApp fixture, `dapp/` (thin SDK only) |
| http://wallet.localhost | `stock` | Giano's stock `wallet-web` container |
| http://app-byo.localhost | `byo` | the same dApp fixture, pointed at the other wallet |
| http://wallet-byo.localhost | `byo` | tenant-built wallet fixture, `wallet-byo/` |

Plus the service endpoints, useful when poking at the stack by hand:

| Origin | What |
| --- | --- |
| http://api.localhost | `wallet-api` — public + admin |
| http://rpc.localhost | anvil devnet JSON-RPC (chain A, 31337) |
| http://bundler.localhost | alto ERC-4337 bundler (chain A) |
| http://rpc-b.localhost | anvil devnet JSON-RPC (chain B, 31338) |
| http://bundler-b.localhost | alto ERC-4337 bundler (chain B) |
| http://paymaster.localhost | paymaster admin console — tenant balances, treasury, roles, health |

## Two chains, by default

The stack runs **two chains** — chain A (`31337`) and chain B (`31338`) — with the same canonical
contracts at the same addresses on both, so multi-chain behaviour is exercised rather than
reasoned about (MC-116–MC-118). Both anvils load the **same** baked `devnet/state.json` (the
dumped state carries accounts, code and storage; the chain id comes from `--chain-id`), and both
are provisioned identically for sponsorship at bring-up (`devnet/provision-sponsorship.mjs`, one
explicit PUT per tenant per chain). One wallet-api, one wallet origin, one Postgres, two chains —
the topology the standalone profile actually uses.

The dApp fixture holds two thin-SDK providers over the same wallet origin, one per chain
(`#send-chain-b` and friends), and reports the chain and the account of every send in its output,
so tests assert both directly. The same passkey produces the **same account address on both
chains** — the property `tests/multichain.spec.ts` exists to verify.

To run the stack with a **single chain** (the on-premises profile, MC-88): comment out the
`anvil-b` and `alto-b` services in `deploy/docker-compose.e2e.yml`, drop the second entry from
each `GIANO_CHAINS` list (wallet-api and wallet-web), and set `SPONSOR_CHAIN_IDS=31337` on the
`sponsorship-provisioner`. The single-chain wallet flows pass unmodified against the two-chain
stack, so this is only needed when specifically exercising the single-chain shape.

To regenerate the baked state with the pinned anvil: `pnpm -F @appliedblockchain/giano-e2e
devnet:generate` (chain A; also writes `devnet/addresses.json`). `devnet:generate:b` produces a
`state-31338.json` and asserts its addresses are identical to chain A's — a divergent pair is
refused rather than committed (MC-119).

The paymaster console is the operator's side of the same sponsorship the dApps are using: open it
next to http://app.localhost and a sponsored send shows up as a falling tenant balance and a new
row under **History**. It reads everything straight from the chain, so it needs no login and works
read-only with no wallet connected.

Every private key, account and fixed address this stack uses is catalogued in
[`docs/E2E-DEV-KEYS.md`](../docs/E2E-DEV-KEYS.md) — all of them public anvil test values, none of
them safe on a network that holds value.

None of them carries a port. That is what this document is about.

## Why names instead of ports

The demo used to speak in ports — `http://app.localhost:4400` talking to
`http://wallet.localhost:8081`, with 8080, 8545 and 4337 threaded through the tenant seed, the
fixtures, the tests, CI and four documents. Every one of those was a place a port could go stale,
and none of them told you anything: `:8081` is not a fact about the wallet, it is a fact about
which container happened to publish which port.

[portless](https://github.com/vercel-labs/portless) is a local reverse proxy that maps
`<name>.localhost` to a loopback port, so the demo can say what it means.

## How it fits together

```
browser                    docker                     host
http://app.localhost  ──▶  portless-port80  ──▶  portless proxy  ──▶  127.0.0.1:4400
        :80                (socat, :80)             (:1355)           (dApp fixture)
                                                         │
                                                         ├──▶  127.0.0.1:8081  (wallet-web container)
                                                         ├──▶  127.0.0.1:8080  (wallet-api container)
                                                         └──▶  ...
```

Two things are worth understanding about that chain.

**Nothing runs as root.** A URL with no port *is* port 80, and macOS and Linux reserve ports below
1024 for root — so the usual price of a port-free URL is `sudo portless proxy start`. Docker can
pay it instead: it already binds this stack's host ports through its own privileged helper, so the
`portless-port80` service holds port 80 and relays every connection to portless, which listens
unprivileged on 1355. `/etc/hosts` is left alone too, since portless only syncs it when it can
write it, and an unprivileged proxy cannot.

**The `Host` header survives.** It has to: portless routes on it, and `wallet-api` resolves tenants
by it (a tenant's RP ID *is* its wallet origin's host). A TCP relay has no opinion about headers,
and portless forwards the original `Host` untouched, so tenant resolution works the same through
the proxy as it did on a direct port.

## Running it

```sh
# from the repo root — --profile portless is what adds the port-80 relay
docker compose --profile portless -f deploy/docker-compose.e2e.yml up --build -d --wait

# register the names, start the proxy if needed, and wait until they answer
pnpm -F @appliedblockchain/giano-e2e portless:up

# the three host-side fixtures (one terminal each)
pnpm -F @appliedblockchain/giano-e2e dapp
pnpm -F @appliedblockchain/giano-e2e wallet-byo
DAPP_PORT=4401 WALLET_URL=http://wallet-byo.localhost pnpm -F @appliedblockchain/giano-e2e dapp
```

Then open **http://app.localhost**. Use Chrome or Firefox: both treat `http://*.localhost` as a
secure context, which is what lets passkeys work (see [HTTP, not HTTPS](#http-not-https)).

`pnpm test` needs none of this ceremony — Playwright's `globalSetup` does the registration itself
and starts the fixtures — but the compose stack and the port-80 relay must already be up.

### Scripts

| Script | Does |
| --- | --- |
| `portless:up` | registers the routes, starts the proxy if it is not running, waits for the names to answer |
| `portless:routes` | registers the routes only — no proxy, no waiting (what CI runs before its own health checks) |
| `portless:port80` | brings up the `portless-port80` relay on its own |
| `portless:proxy` | runs the proxy on port 80 directly; needs `sudo`, and then the relay is unnecessary |
| `portless:down` | removes the routes and stops the proxy |
| `portless:list` | shows the active routes |

## Where the names live

[`origins.mjs`](./origins.mjs) is the single source of truth — the name/port table, and the
`ORIGINS` map built from it. Everything reads from there:

- the fixtures (`dapp/serve.mjs`, `wallet-byo/serve.mjs`), for what they listen on and what they
  bake into their bundles;
- [`playwright.config.ts`](./playwright.config.ts), for `baseURL` and the `webServer` entries;
- the tests, via `tests/helpers.ts`;
- and, by hand rather than by import, the tenant seed in `deploy/docker-compose.e2e.yml`.

That last one is the seam to watch: compose is YAML and cannot import a module, so the origins in
`TENANTS_SEED`, `GIANO_ALLOWED_DAPP_ORIGINS`, `GIANO_RPC_URL`, `GIANO_BUNDLER_URL` and `GIANO_RP_ID`
have to be kept in step with `origins.mjs` by hand.

### Adding or renaming a name

Add a row to `ROUTES` in `origins.mjs` and it is registered on the next `portless:up`. Renaming is
the same edit — with one caveat: `wallet` and `wallet-byo` are also **WebAuthn RP IDs**, because a
tenant's RP ID must equal its wallet origin's host. Renaming those two means updating `TENANTS_SEED`
and `GIANO_RP_ID` in the compose file to match, and existing passkeys minted under the old RP ID
will not be offered for the new one.

Route names live in portless's machine-global namespace, so `app` and `api` are shared with every
other portless project on the machine. `portless alias` reports a conflict rather than silently
stealing a name; renaming in `origins.mjs` is the fix.

## HTTP, not HTTPS

portless defaults to HTTPS on 443 with a locally-generated CA. This demo deliberately uses plain
HTTP, because `http://*.localhost` is *already* a secure context in Chrome and Firefox: WebAuthn,
`crypto.subtle` and the popup flow behave exactly as they would over TLS. Nothing here depends on
the difference — there are no cookies anywhere in the stack, so there is no `Secure` or
`SameSite=None` behaviour that HTTP would mask; sessions live in `localStorage`.

What HTTPS *would* cost is a locally-minted root CA marked trusted in the developer's keychain, and
on CI a `certutil` install into Chromium's NSS store (Playwright's Chromium on Linux does not read
the system trust store). The fallback for that — `ignoreHTTPSErrors` — is the one option to avoid:
a cert-error origin is exactly where Chrome gets fussy about WebAuthn, which is what this suite
exists to test. So: HTTP, and the port is gone anyway.

## CI

CI takes the sudo route instead of the relay: on a throwaway runner sudo is free, and one less
moving part is worth more than symmetry with local dev. `.github/workflows/e2e.yml` registers the
routes unprivileged, then starts the proxy on port 80 under sudo — which also means the root proxy
syncs `/etc/hosts`, removing any doubt about `*.localhost` resolution on Linux. That is why the CI
compose step does **not** pass `--profile portless`: the relay would only fight the proxy for the
port.

CI runs Node 24, because portless requires it.

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `Nothing is serving the demo's names on port 80` | the relay is not up — `pnpm -F @appliedblockchain/giano-e2e portless:port80` (or take the sudo route) |
| Every name returns a portless **404** page | routes are not registered — `pnpm -F @appliedblockchain/giano-e2e portless:up`; check with `portless:list` |
| A name returns **502** | the route is registered but nothing is listening behind it: the compose stack is down, or that host fixture is not running |
| `EADDRINUSE` on the relay | something else already holds port 80 |
| `portless alias` reports a route conflict | another portless project has claimed that name — rename the route in `origins.mjs` |
| Names resolve but hit the wrong app | a stale route from an earlier layout — `portless:down`, then `portless:up` |
| Suite reuses a stale fixture | `webServer` has `reuseExistingServer: true`; kill whatever is on 4400/4401/8082 and re-run |
| dApp rejected as an unknown origin | the tenant seed still allow-lists a ported origin — the origins in `deploy/docker-compose.e2e.yml` must match `origins.mjs` |
| Passkey prompt never appears in a real browser | not a portless problem: use Chrome or Firefox, which treat `http://*.localhost` as a secure context |

`portless doctor` checks the proxy, the routes, DNS resolution and CA trust in one go, and is the
right first command when the names misbehave.

## The suite itself

```sh
pnpm -F @appliedblockchain/giano-e2e exec playwright install chromium
pnpm -F @appliedblockchain/giano-e2e test
```

39 tests across four files: the stock wallet flow, the BYO wallet flow, tenant isolation (distinct
RP IDs, cross-tenant token rejection, Host-scoped `/.well-known/webauthn`), and gas sponsorship
(accounting, pre-approval refusals, invariants). WebAuthn uses the CDP virtual authenticator on the
popup page, so the suite is Chromium-only and never prompts for a real passkey.
