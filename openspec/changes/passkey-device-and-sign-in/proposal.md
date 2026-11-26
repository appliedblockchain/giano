# Proposal

## Why

Manual testing of the multi-passkey flow showed two problems.

- The management list could not tell passkeys apart. Two rows read "Another device · 25/11/2026", with a raw transport list ("internal/hybrid"). A user needs the device, the browser and the passkey service to decide which passkey is which.
- The wallet origin offered two sign-in buttons. A passkey added from another device is created on the device that uses it, so "Use a passkey created on another device" was untrue, and "Sign in with passkey" only offered the passkeys of the user the browser last knew.

## What Changes

- wallet-api records the device family and browser of the request that created each passkey (its User-Agent), at registration and at the deposit of a passkey added from another device, and carries them when the pending addition is bound. `GET /v1/me/credentials` returns `addedFrom: { device, browser }`, and the pending-addition poll returns it once a key is deposited.
- wallet-core and wallet-kit carry it (`PasskeyAddedFrom`) onto owner rows and onto the add flow's consent step.
- The stock wallet shows each passkey as "Passkey added <date> on iPhone · Safari" over "Stored in Apple Passwords · synced", without the raw transports. Device A's consent for a passkey from another device shows where it was created and uses that as the default name.
- The wallet origin has one sign-in button. "Sign in with passkey" is discoverable: the browser lists every passkey the device holds, whichever wallet it belongs to. `signInWithExistingPasskey` is kept as a deprecated alias.

## Capabilities

### New Capabilities

- `passkey-identification`: what the wallet records and shows to tell passkeys apart, and the single discoverable sign-in.

### Modified Capabilities

None.

## Impact

wallet-api (migration `0015_passkey_added_from.sql`, credentials and pending-addition responses, OpenAPI), wallet-core and wallet-kit (changeset), wallet-web and the BYO reference. The User-Agent is self-reported, so the device and browser are display only. Passkeys added before this change show no device.
