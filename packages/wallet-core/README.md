# @appliedblockchain/giano-wallet-core

The low-level Giano wallet library: an EIP-1193 provider backed by a passkey smart account
(viem), plus the provider-injection seam that connects it to a wallet-api. It runs inside a
wallet origin. Most wallets use it through
[`@appliedblockchain/giano-wallet-kit`](https://github.com/appliedblockchain/giano/tree/main/packages/wallet-kit);
use it directly only to build a wallet without the kit. dApps never install it; they use
[`@appliedblockchain/giano-connector`](https://github.com/appliedblockchain/giano/tree/main/packages/connector).

## Installation

Published to **GitHub Packages** under the `@appliedblockchain` scope:

```ini
# .npmrc
@appliedblockchain:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```

```bash
npm install @appliedblockchain/giano-wallet-core viem
```

The full wallet integration is described in
[`specs/INTEGRATION.md`](https://github.com/appliedblockchain/giano/blob/main/specs/INTEGRATION.md)
and
[`specs/DEVELOPER-GUIDE.md`](https://github.com/appliedblockchain/giano/blob/main/specs/DEVELOPER-GUIDE.md).

## Suggest using a phone

Set `passkeyDevicePreference: "prefer-mobile"` on both `createGianoProvider`
and `createWalletApiInjection` when constructing your wallet. Omit it (or use
`"browser-default"`) to retain the browser's normal chooser. The shared
`PasskeyDevicePreference` type is exported by wallet-core.

The preference adds WebAuthn's `hybrid` UI hint to initial registration,
authentication, and subsequent signatures, including restored sessions. Browsers
and operating systems may ignore it; local passkeys and security keys remain
eligible. It does not prove that a phone was used or control passkey syncing.
Cancellation never causes an automatic retry. Explicit current-device and
claim-device credential additions remain unhinted so the enrollment target
stays clear; existing owner signatures still use the preference.

The hint is sent whatever device the user is on, because detecting a phone would mean UA sniffing. On a phone, the browser may offer another device first; the phone's own passkey stays selectable. If most of your users are on phones, keep `browser-default`.

## Manage the owners of an account

wallet-core exports the building blocks for reading and changing the owner set of a
Giano smart account:

- `readOwnerSet(client, wallet)` reads the owners from the account contract on one chain.
- `encodeAddOwnerPublicKey(x, y)`, `encodeAddOwnerAddress(address)` and
  `encodeRemoveOwnerAtIndex(index, ownerBytes)` build the calldata of an owner change.
  The account sends it to itself, as an ordinary user operation.
- `publicKeyOwnerBytes(x, y)` and `addressOwnerBytes(address)` return an owner's
  on-chain encoding, which `encodeRemoveOwnerAtIndex` and `ownerFingerprint` take.
- `parseP256PublicKey(key)` turns a passkey's public key into the `(x, y)` coordinates
  that `encodeAddOwnerPublicKey` takes.

`parseP256PublicKey` accepts the shapes a key usually arrives in, as hex, a `Uint8Array`
or an `ArrayBuffer`:

- the SPKI key from `AuthenticatorAttestationResponse.getPublicKey()`
- an uncompressed point (`0x04 ‖ x ‖ y`, WebCrypto's `raw` export)
- the bare coordinates (`x ‖ y`, viem's `createWebAuthnCredential().publicKey`)

It throws `InvalidP256PublicKeyError` for any other shape, for another algorithm or
curve, for a compressed point, and for a point that is not on the P-256 curve.

```ts
import {
	encodeAddOwnerPublicKey,
	parseP256PublicKey,
} from "@appliedblockchain/giano-wallet-core";

const response = credential.response as AuthenticatorAttestationResponse;
const { x, y } = parseP256PublicKey(response.getPublicKey()!);
const data = encodeAddOwnerPublicKey(x, y);
// send { to: accountAddress, data } as a call of a user operation
```
