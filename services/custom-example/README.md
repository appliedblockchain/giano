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

## Run it

The wallet stack must be running. Bring up the E2E stack (wallet origin + wallet-api + bundler +
devnet), then start the dApp:

```sh
# from the repo root — see the root README "Option A"
docker compose -f deploy/docker-compose.e2e.yml up --build

# then, in another terminal
pnpm demo:dev        # http://app.localhost:4400
```

Open **http://app.localhost:4400** and connect. That origin is already allow-listed by the E2E
wallet stack, so no extra configuration is needed.

## Configuration

Defaults target the local E2E stack. Override with `VITE_*` env vars (e.g. in a `.env` file) for
other networks:

| Var | Default | Purpose |
| --- | --- | --- |
| `VITE_WALLET_URL` | `http://wallet.localhost:8081` | wallet origin (popup) |
| `VITE_RPC_URL` | `http://localhost:8545` | read-path RPC (balances, metadata) |
| `VITE_CHAIN_ID` | `31337` | chain id |
| `VITE_TEST_ERC20` | devnet PrivateERC20 | prefilled token in the ERC-20 panel |
