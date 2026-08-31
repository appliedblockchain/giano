# @appliedblockchain/giano-connector

The thin Giano SDK: connect any dApp to a deployed **Giano wallet origin** (popup) with
wagmi/RainbowKit integration. From 1.0.0 the default entry point contains **no WebAuthn,
credential-storage or bundler code** — all wallet trust lives in the Giano-shipped wallet
origin (`wallet.yourapp.com`) and the wallet-api behind it.

## Installation

Published to **GitHub Packages** under the `@appliedblockchain` scope:

```ini
# .npmrc
@appliedblockchain:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```

```bash
npm install @appliedblockchain/giano-connector viem
# for wagmi / RainbowKit integration:
npm install wagmi @rainbow-me/rainbowkit
```

`viem` is a required peer; `wagmi` and `@rainbow-me/rainbowkit` are optional peers.

> **Scope caveat:** routing the whole `@appliedblockchain` scope to GitHub Packages means the
> project cannot also fetch the public `@appliedblockchain/silentdatarollup-*` packages from
> npmjs (internal Giano devDependencies only — consumers never need them).

## Quick start

```ts
import { createGianoWalletProvider, createGianoConnector, giano } from '@appliedblockchain/giano-connector';
import { createConfig, custom } from 'wagmi';
import { baseSepolia } from 'wagmi/chains';

const provider = createGianoWalletProvider({
  walletUrl: 'https://wallet.yourapp.com',   // your deployed Giano wallet origin
  chain: baseSepolia,
});

// wagmi
const config = createConfig({
  chains: [baseSepolia],
  transports: { [baseSepolia.id]: custom(provider) },
  connectors: [createGianoConnector({ provider })],
});

// or RainbowKit
const wallet = giano({ provider });
```

What happens at runtime:

- `eth_call`, `eth_chainId` and other **read paths are answered dApp-side** (no popup).
- `eth_requestAccounts`, `eth_sendTransaction`, `personal_sign`, `eth_signTypedData_v4`
  open the wallet popup, where the user approves with a passkey on the wallet origin.
- The session (`accounts`, `chainId`) is cached in `localStorage`, so `eth_accounts`
  answers instantly across reloads without a popup.
- `waitForUserOperationReceipt` polls the wallet-api's public receipt endpoint — dApps
  never need a bundler URL.

### Chains

The `chain` you pass is **declared to the wallet origin** in the popup handshake, and the wallet
grants it or refuses the connection outright. Naming it is mandatory and costs nothing — the
parameter was already required; there is no default chain anywhere.

- The chain is **fixed for the provider's life**. To address another chain, construct another
  provider — two instances against the same wallet origin coexist with separate sessions and
  caches. `provider.chainId` is the granted chain; `provider.supportedChainIds` lists every
  chain the wallet origin advertised on the last connect.
- If the wallet origin does not serve your chain, connecting rejects with
  `UnsupportedChainError` (EIP-1193 code `4902`) carrying `requestedChainId` and
  `supportedChainIds` — permanent, resolved by the wallet operator. A `4901` means the chain is
  served but temporarily unreachable, and is worth retrying.
- `wallet_switchEthereumChain` / `wallet_addEthereumChain` are refused with `4200`, and the
  wagmi connector's `switchChain` throws a typed `UnsupportedChainSwitchError` — build chain
  pickers by constructing a provider per chain, not by switching.
- The same passkey controls the **same smart-account address on every chain the wallet origin
  serves**; the account deploys lazily on each chain with its first transaction there.

### Popup requirements

- Call `connect()` / `eth_requestAccounts` from a **user gesture** (Safari blocks popups
  otherwise; the SDK opens `about:blank` synchronously and navigates after).
- Do **not** send `Cross-Origin-Opener-Policy: same-origin` from the dApp — it severs
  `window.opener` and the transport times out. Use `same-origin-allow-popups`.
- Popup blocked → typed `TransportError` with code `POPUP_BLOCKED`; user rejection →
  `TransportRpcError` with EIP-1193 code `4001`.

## Migrating from 0.x (embedded mode)

In 0.x your application WAS the wallet: your origin owned the passkeys and your bundle
carried the signing code. That model is **gone** — this package no longer ships it, in any
subpath. To migrate:

1. Deploy the Giano containers (`giano-wallet-api`, `giano-wallet-web`) in your stack —
   see `deploy/docker-compose.reference.yml` in the Giano repo.
2. Replace `createGianoProvider({ bundler, injection, … })` with
   `createGianoWalletProvider({ walletUrl, chain })`.
3. Delete your `GianoProviderInjection` implementation, WebAuthn plumbing and bundler
   client — the wallet origin owns all of it now.

⚠️ Passkeys are bound to the origin that created them: wallets created in embedded mode
(RP = your dApp origin) are not automatically usable from the wallet origin. Related
Origin Requests (`/.well-known/webauthn`) can bridge specific origins — see the Giano
integration docs.

## Entry points

| Import | Contents |
| --- | --- |
| `.` | thin SDK: `createGianoWalletProvider`, `createGianoConnector`, `giano`, transport errors | 
