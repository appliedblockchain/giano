# @appliedblockchain/giano-connector

A wagmi connector and RainbowKit wallet for Giano passkey (WebAuthn) smart wallets.

## Installation

The package is published to **GitHub Packages** under the `@appliedblockchain` scope. In the
consuming project:

```ini
# .npmrc
@appliedblockchain:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```

```bash
npm install @appliedblockchain/giano-connector viem
# for the wagmi/RainbowKit integration also:
npm install wagmi @rainbow-me/rainbowkit
```

`viem` is a required peer dependency. `wagmi` and `@rainbow-me/rainbowkit` are **optional**
peers — only needed if you use `createGianoConnector` / `giano` (the RainbowKit wallet); the
`/node` entry point works without them.

> **Scope caveat:** routing the whole `@appliedblockchain` scope to GitHub Packages means the
> same project cannot also fetch the public `@appliedblockchain/silentdatarollup-*` packages from
> npmjs. Those are internal devDependencies of the Giano repo and are never needed by consumers.

## Entry points

| Import | Contents | Needs wagmi/RainbowKit |
| --- | --- | --- |
| `@appliedblockchain/giano-connector` | everything (same as `/web`) | yes |
| `@appliedblockchain/giano-connector/web` | wagmi connector + RainbowKit wallet + provider | yes |
| `@appliedblockchain/giano-connector/node` | provider, accounts, injection types — no wagmi/RainbowKit | no |

## Usage

### wagmi / RainbowKit (web)

```ts
import { createGianoProvider, createGianoConnector, giano } from '@appliedblockchain/giano-connector';
import { getGianoDeployment } from '@appliedblockchain/giano-contracts';

const { factory } = getGianoDeployment(chain.id);

const { gianoProvider } = createGianoProvider({
  initialChainId: chain.id,
  bundler,                                  // viem BundlerClient
  chains: [chain],
  transports: { [chain.id]: transport },
  injection,                                // GianoProviderInjection implementation
  gianoSmartWalletFactoryAddress: factory,
});

// plain wagmi:
const connector = createGianoConnector({ provider: gianoProvider });

// or as a RainbowKit wallet:
const wallet = giano({ provider: gianoProvider });
```

### Node.js

```ts
import { createGianoProvider, toGianoSmartAccount } from '@appliedblockchain/giano-connector/node';
```

The `/node` entry exposes the provider, `toGianoSmartAccount`, deployment helpers and the
`GianoProviderInjection` types without pulling in wagmi or RainbowKit.

## Main exports

- `createGianoProvider(options)` — EIP-1193 provider driving the Giano smart account. Accepts an
  optional `logger` (`GianoLogger`); by default the provider is silent except for errors.
- `createGianoConnector({ provider })` — wagmi connector (also exposes
  `waitForUserOperationReceipt`).
- `giano({ provider })` — RainbowKit wallet factory.
- `toGianoSmartAccount(...)`, `getWebAuthnAccount(...)` — viem smart-account implementations.
- `GianoProviderInjection` — the seam a host application implements to supply credential
  storage/ceremony callbacks and (optionally) server-side user-operation submission.
- Deployment helpers: `isSmartAccountDeployed`, `ensureSmartAccountIsDeployed`,
  `waitForSmartAccountDeployment`.

## Building

```bash
pnpm build   # tsup: ESM + CJS + d.ts for index, index-web, index-node
```
