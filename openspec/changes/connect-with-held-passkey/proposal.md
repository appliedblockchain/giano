# Proposal

## Why

A connect without a session signs in with the passkeys of the external user id the browser stores, or creates a wallet when that user has none. That id names whom the browser last knew, not which passkeys the device holds:

- A device that joined a wallet through a pending addition (WM-18) still stores its own random id. Its first connect from an application found no credentials and **registered a new passkey and a new, empty wallet**.
- A device that last used another wallet stores that wallet's user. Its connect asked the browser only for that user's passkeys, so the passkey it had just been given was **never offered**. And a sign-in challenge bound to that user would refuse the new passkey anyway (C3).
- A returning user on a fresh browser, or after clearing site data, creates a new wallet instead of signing in with their synced passkey.

Separately, every passkey for a wallet origin carries the tenant's brand as its name, so a password manager's picker shows several identical entries and the user cannot tell which belongs to which wallet.

## What Changes

- wallet-api: `POST /v1/webauthn/options` accepts `discoverable: true` (sign-in only). It issues a challenge bound to no user and lists no credentials; the passkey that answers names its own user and wallet. The claim response also returns the wallet being joined.
- wallet-core: the wallet-api injection takes a per-connect choice (`setConnectChoice`). `existing` signs in with any passkey the device holds (discoverable). `new` creates a wallet, under a fresh external user id when the stored one already has a wallet. A session still decides over any choice, now with a discoverable challenge. The wallet origin's "use a passkey created on another device" sign-in uses a discoverable challenge too. `depositPasskeyIntoPendingAddition` can name the passkey after the wallet being joined.
- wallet-kit: the device remembers that it holds a passkey (after a sign-in, a registration or a claim). The connect consent carries an offer: `session`, `held-passkey` (approve signs in with a held passkey; the alternative creates a new wallet) or `default` (as before; the alternative signs in with a held passkey). The host sets the injection's choice for that connect alone. New passkeys are named `<brand> · 0x1234…abcd` when the wallet is known (adding on this device, a claim), else `<brand> · YYYY-MM-DD`.
- Stock wallet and BYO reference: the connect screen shows the second choice; the claim screen shows the wallet being joined.

## Capabilities

### New Capabilities

- `passkey-sign-in`: how a connect without a session chooses between a held passkey and a new wallet, and how passkeys are named.

### Modified Capabilities

None.

## Impact

wallet-api (options and claim responses, OpenAPI), wallet-core and wallet-kit (changeset, minor), wallet-web and the BYO reference. No schema, contract or session-model change. The primary button keeps its label ("Continue with passkey"), so existing integrations and tests are unchanged. A discoverable challenge lets any credential of the tenant answer it, which is what possession of a passkey proves; bound challenges are unchanged for every other path.
