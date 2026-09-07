# Giano sample dApp

A small, deliberately simple demo of the **thin two-origin** Giano integration, built with
**Vite + React + Chakra UI**. All wallet trust (passkeys, signing, consent) lives on the wallet
origin popup — this dApp bundle ships no WebAuthn or bundler code and talks to the wallet only
through the `createGianoWalletProvider` EIP-1193 provider.

What it shows:

- **Wallet basics** — connect / disconnect, send a 0 ETH user-operation, sign a message
  (`personal_sign`) and typed data (`eth_signTypedData_v4`).
- **ERC-20 panel** — enter any token address, read its name/symbol/decimals/balance, then
  **transfer** (destination defaults to your own account), sign+submit an **approve** transaction,
  and sign an **EIP-2612 permit** (the signature and its `v`/`r`/`s` are displayed; tokens without
  permit support are reported cleanly).
- **Gasless sponsorship** — every send goes through **Giano's paymaster**: the wallet origin runs
  an ERC-7677 sponsorship check before it asks for a passkey, so an allow-listed call is **covered**
  and a call nobody sponsors is **refused** up front (no approval, no passkey prompt, nothing
  charged). The panel's **Call an unlisted contract** button exercises that refusal path.

## Run it

The wallet stack must be running. Bring up the E2E stack (wallet origin + wallet-api + bundler +
devnet), then start the dApp:

```sh
# from the repo root — see the root README "Option A"
# --profile portless adds the container that lends the stack port 80, so no sudo is needed
docker compose --profile portless -f deploy/docker-compose.e2e.yml up --build
pnpm -F @appliedblockchain/giano-e2e portless:up

# then, in another terminal
pnpm demo:dev        # http://app.localhost
```

Open **http://app.localhost** and connect. That origin is already allow-listed by the E2E
wallet stack, so no extra configuration is needed. Vite still listens on port 4400 — that is
simply the loopback target portless publishes as `app.localhost` (see `e2e/origins.mjs`).

## Configuration

Defaults target the local E2E stack. Override with `VITE_*` env vars (e.g. in a `.env` file) for
other networks:

| Var | Default | Purpose |
| --- | --- | --- |
| `VITE_WALLET_URL` | `http://wallet.localhost` | wallet origin (popup) |
| `VITE_RPC_URL` | `http://rpc.localhost` | read-path RPC (balances, metadata) |
| `VITE_CHAIN_ID` | `31337` | chain id |
| `VITE_TEST_ERC20` | devnet PrivateERC20 | prefilled token in the ERC-20 panel |
| `VITE_APP_LABEL` | _(unset)_ | free-text badge next to the title, to tell instances apart |

## Two tenants side by side

The e2e stack seeds two tenants against one backend, each with its own wallet origin. This one
dApp can serve both — point a second instance at the other wallet origin. Both dApp origins are
already allow-listed by `deploy/docker-compose.e2e.yml`:

```sh
pnpm demo:stock   # -> http://app.localhost,     wallet http://wallet.localhost
pnpm demo:byo     # -> http://app-byo.localhost, wallet http://wallet-byo.localhost
```

Tenant "byo" also needs its wallet origin served: `pnpm -F @appliedblockchain/giano-e2e wallet-byo`.

> **Do not run these while the Playwright suite runs.** The suite drives the minimal fixture in
> `e2e/dapp/` on these same two ports — 4400/4401 are the only dApp origins the e2e tenants
> allow-list, so both apps compete for them. Playwright's `reuseExistingServer: true` will
> silently adopt this app instead of the fixture and every test then fails on a missing
> `#connect`. Stop these dev servers before running `pnpm -F @appliedblockchain/giano-e2e test`.
