# Proposal

## Why

A user who holds passkeys on several devices cannot tell from the wallet where each one lives. The management list shows a creation date, a transport and a fingerprint. "Which of these is in my password manager, and which only exists on the laptop I am about to sell?" is exactly the question a user asks before removing one. An integrating client relies on the stock management UI for this (PS-1: "lists every passkey on the account and shows where each one is stored").

## What Changes

- wallet-api records, for each passkey, what its authenticator reports: the AAGUID (which names the provider), whether it can be synced (`singleDevice` / `multiDevice`), and whether it is backed up now. It records them at registration and when a passkey is deposited from another device, and refreshes the two flags at each sign-in.
- `GET /v1/me/credentials` returns a `storage` object per credential: the provider name (from a short, hand-kept AAGUID table), `synced`, `deviceType` and the raw `aaguid`.
- wallet-core types it (`PasskeyStorage`, optional on `RegistryCredential`). wallet-kit carries it onto each `OwnerRow` and re-exports the type.
- The stock wallet shows one line per passkey: "Stored in Google Password Manager · synced", "On a security key · this device only", "This device only", or "Where it is stored was not recorded" for passkeys registered before this change. The BYO reference shows it too.

## Capabilities

### New Capabilities

- `passkey-storage`: what the wallet records and shows about where a passkey is stored, and the rule that it is never authority.

### Modified Capabilities

None.

## Impact

wallet-api (migration `0014_passkey_storage.sql`, three nullable columns on `credentials` and on `pending_additions`; the credentials response; OpenAPI), wallet-core and wallet-kit types (changeset), wallet-web and the BYO reference. No contract, address, session or authorisation change. Existing rows stay NULL until their next sign-in, and their provider stays unknown: the AAGUID is only in the registration data.

The AAGUID table is hand-kept rather than vendored: the community list (github.com/passkeydeveloper/passkey-authenticator-aaguids) carries no licence. An AAGUID is chosen by the authenticator and, with attestation `none`, unproven. That is acceptable for a label and is why the value is display only.
