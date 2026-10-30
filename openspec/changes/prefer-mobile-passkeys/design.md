# Design

## Context

See proposal.md for motivation and specs/passkey-device-preference/spec.md for behavior. Read-only inspection found:

- `wallet-kit/src/config.ts` owns `RawWalletConfig`, `WalletConfig`, normalization, and runtime loading. Neither currently has device preference.
- `wallet-kit/src/runtimes.ts` constructs the shared API injection and per-chain providers. `wallet-kit/src/management/controller.ts` invokes passkey addition.
- `wallet-core/src/provider.ts` creates credentials and constructs WebAuthn accounts on new, existing, and restored-session paths. `account/get-credential.ts` builds explicit authentication options; `provider-injection/wallet-api/create-wallet-api-injection.ts` also directly calls `navigator.credentials.get` for existing-passkey discovery.
- `account/get-web-authn-account.ts` constructs additional WebAuthn accounts. Signing later delegates to `owner.sign` in `account/toGianoSmartAccount.ts`; updating sign-in requests alone misses these signatures.
- The installed viem 2.57.10 `toWebAuthnAccount` accepts `getFn`; `createWebAuthnCredential` delegates creation to ox, which exposes `createFn`. These hooks allow request decoration without a dependency change or replacement signature implementation.
- `management/create-passkey.ts` handles new-credential enrollment for both current-device and claimed additions. The claim flow already runs on the intended enrolling device.
- `services/wallet-web` loads `/config.json`; its entrypoint renders separate scalar and multi-chain templates. The thin connector only asks the wallet origin to perform operations.

Existing transaction-review specs require consent and sponsorship checks before approval. This proposal adds no exception to those gates. No existing OpenSpec capability owns authenticator preference; the flat `passkey-device-preference` capability is new.

## Goals / Non-Goals

**Goals:** One opt-in wallet setting; consistent coverage of every signature-producing account construction path; stable defaults; request-level evidence and real-device verification.

**Non-Goals:** Enforcing phone-only credentials, controlling passkey synchronization/storage, remembering a particular phone, adding a device chooser to the dApp, tenant database settings, or implementing a QR transport. Browser/OS UI remains authoritative.

## Decisions

### D1. Use a narrow wallet-owned preference

Add optional `passkeyDevicePreference?: "browser-default" | "prefer-mobile"` to public wallet-core construction APIs and wallet-kit raw/resolved config. Resolve omission to browser-default without making existing manually constructed `WalletConfig` objects fail type checking. Validate configured values at kit and core boundaries. Use one shared exported core type to avoid drift.

The kit passes the value to provider and API-injection construction, including all per-chain runtimes; direct wallet-core consumers can opt in without wallet-kit. No connector or transport schema extension is needed. Application-supplied preference fields never participate in wallet configuration resolution. Prefer this fixed vocabulary over an arbitrary WebAuthn-options object, which could accidentally expose security-sensitive overrides.

### D2. Decorate WebAuthn requests at their boundaries

Use a small shared helper that adds only `publicKey.hints = ["hybrid"]` in prefer-mobile mode, retaining every other option. Leave requests untouched in default mode. Never set `authenticatorAttachment: "cross-platform"` or force `transports: ["hybrid"]`: both can narrow choices and a cross-platform authenticator is not necessarily a phone.

Thread a decorated, correctly bound `getFn` into every `toWebAuthnAccount` construction, including newly created, authenticated, and restored credentials; decorate the direct discovery and credential-get requests too. Use the creation hook at initial registration. Preserve existing dependency hooks and test mocks rather than overriding a caller's functions. Keep any necessary DOM typing extension local and narrow; no blanket `any` cast or global credential API monkey patch.

The preference carries through ordinary signing, typed-data signing, raw operations, and management owner signatures via the account's existing sign method. The lower-level `toGianoSmartAccount` continues consuming owners; it does not invent new prompts or intercept external non-passkey signers.

### D3. Explicit new-device enrollment omits the hint

Keep `depositPasskeyIntoPendingAddition` registration unhinted for current-device and claimed additions. The UI names the enrollment target explicitly; adding a phone preference there can redirect a phone user toward a second device. Existing owner signatures authorizing the addition still inherit D2. Do not change claim codes, fingerprints, on-chain owner consent, or credential eligibility.

### D4. Deliver runtime configuration and truthful guidance

Expose `GIANO_PASSKEY_DEVICE_PREFERENCE` with default `browser-default` through both stock wallet JSON templates, the entrypoint's explicit multi-chain substitution allow-list, and Vite/local configuration. Validate before ceremonies. Document the equivalent direct kit/core options and runtime env setting in package READMEs and the integration/developer guides. Custom wallets receive the same SDK behavior; their own UI chooses where to present guidance.

Stock wallet connect, approval, and management authentication views share short conditional guidance, for example: “Your browser may offer a phone or QR code. You can also choose another available passkey.” Enrollment screens keep their explicit current-device wording. Do not infer success or device identity from the hint.

### D5. Keep unsupported browsers and cancellations on the existing paths

Hints are advisory and may be ignored. Send the hint without UA sniffing or feature probing; accept otherwise valid local, synced, or security-key credentials. Do not automatically retry after NotAllowedError or AbortError, since these include deliberate cancellation. Browser-default remains a deployment rollback option. No changes to RP ID, user verification, session identity, credential allow-lists, or backend verification.

References: [WebAuthn hints](https://www.w3.org/TR/webauthn-3/#enum-hints), [Chrome guidance and OS limitations](https://developer.chrome.com/blog/passkeys-updates-chrome-129). These support a suggestion, not a guarantee of phone selection.

## Risks / Trade-offs

- Browser or OS ignores hints → document the limitation and verify actual desktop/phone behavior manually; automated mocks only prove request construction.
- One account path misses the hook → enumerate every `toWebAuthnAccount` construction and test initial, restored, and discovered credentials plus management signatures.
- Phone-preference copy conflicts with local enrollment → apply the explicit enrollment exception and test both additions and claims.
- Public type/config drift → retain optional properties, test omission and invalid input, and add a minor changeset for wallet-core and wallet-kit during implementation.
- Native chooser may still prefer a local option → accept that result; phone preference is not a security policy.

## Migration Plan

1. Implement additive APIs and coverage without changing any deployment defaults or dependency pins.
2. Run package tests/typechecks, repository lint, and freshly rebuilt E2E coverage; record real-browser/phone results separately.
3. Publish wallet-core and wallet-kit with a changeset; rebuild wallet-web from compatible workspace versions. The example's published connector needs no change.
4. Enable the environment variable only in a chosen local/demo wallet deployment and inspect its rendered config. Roll back by setting browser-default or removing the setting. No data migration or contract redeployment is needed.
