# @appliedblockchain/giano-wallet-kit

The Giano wallet SDK: the framework-agnostic orchestration a Giano wallet origin is built
from. It provides per-chain runtimes, the transport host with its consent gate, the
wallet-management controller, and React bindings at `@appliedblockchain/giano-wallet-kit/react`.
The stock Giano wallet (`services/wallet-web`) is built on it; a custom wallet brings its
own UI on top. dApps never install it; they use
[`@appliedblockchain/giano-connector`](https://github.com/appliedblockchain/giano/tree/main/packages/connector).

## Installation

Published to **GitHub Packages** under the `@appliedblockchain` scope:

```ini
# .npmrc
@appliedblockchain:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```

```bash
npm install @appliedblockchain/giano-wallet-kit viem
```

The full wallet integration is described in
[`specs/INTEGRATION.md`](https://github.com/appliedblockchain/giano/blob/main/specs/INTEGRATION.md)
and
[`specs/WALLET-SDK-SPECS.md`](https://github.com/appliedblockchain/giano/blob/main/specs/WALLET-SDK-SPECS.md).

## Suggest using a phone

Set `passkeyDevicePreference: "prefer-mobile"` in the raw wallet config passed to
`resolveWalletConfig`, or in your custom `WalletConfig`. The kit passes it to the
shared API injection and every chain's provider. Omission or `"browser-default"`
retains the existing browser chooser. Unsupported values fail validation.

This is owned by the wallet deployment; an integrating dApp cannot override it
through the connector, request payload, or popup URL. Explain to users that the
browser may offer a phone/QR flow and that another available passkey can still
be selected. It is a suggestion, not a phone-only policy. Explicit current-device
and claim-device enrollment omits the suggestion for the new credential.

The hint is sent whatever device the user is on, because detecting a phone would mean UA sniffing. On a phone, the browser may offer another device first; the phone's own passkey stays selectable. If most of your users are on phones, keep `browser-default`.
