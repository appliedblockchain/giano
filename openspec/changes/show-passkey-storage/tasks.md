# Tasks

## 1. wallet-api

- [x] 1.1 Migration `0014_passkey_storage.sql`: `aaguid`, `device_type`, `backed_up` on `credentials` and `pending_additions`; schema columns.
- [x] 1.2 Record them at registration and at fill, carry them at complete, refresh the flags at sign-in.
- [x] 1.3 `storage` on `GET /v1/me/credentials`, the provider from `passkey-providers.ts`; regenerate OpenAPI.
- [x] 1.4 Tests: registration with a known AAGUID and backup flags, an unknown and all-zero AAGUID, a passkey added from another device, a sign-in that changes the backup state.

## 2. SDK

- [x] 2.1 wallet-core `PasskeyStorage`, optional `storage` on `RegistryCredential`.
- [x] 2.2 wallet-kit `OwnerRow.storage` for owners and strays, `PasskeyStorage` re-exported; tests for a row with storage, without a registry row, and from a wallet-api that does not report it.
- [x] 2.3 Changeset (wallet-core and wallet-kit minor).

## 3. Wallets and e2e

- [x] 3.1 Stock wallet: one storage line per passkey (`manage-owner-storage`); BYO reference: `byo-manage-owner-storage`.
- [x] 3.2 e2e: a device-only passkey reads "This device only"; with a synced device B, both devices list device B's passkey as "Synced" and device A's as "This device only".
