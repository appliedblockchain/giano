# Tasks

## 1. Wallet-core preference and ceremony coverage

- [ ] 1.1 Add the exported optional preference type, validation, and request decorator in wallet-core. Verify omitted/default requests retain their options, prefer-mobile adds only the hybrid hint, and invalid values fail before credentials APIs run.
- [ ] 1.2 Thread preference through provider creation, direct credential retrieval, and API-injection discovery. Add tests covering initial registration, selected-credential and discoverable sign-in, preserving challenges, RP scope, required user verification, credential IDs, and cancellation semantics; run wallet-core tests and typecheck.
- [ ] 1.3 Apply the decorated getFn at every WebAuthn-account construction, including new, authenticated, and restored sessions. Extend signing/provider tests to observe options for transaction, personal-message, typed-data, raw-operation, and management signatures; verify restore creates no extra ceremony and default behavior is unchanged.
- [ ] 1.4 Keep current-device and claim-device new-credential registration unhinted. Extend management tests to verify both enrollment exceptions, retained fingerprint consent, and the hybrid hint on authorizing owner signatures.
- [ ] 1.5 Document direct wallet-core configuration, browser limitations, and enrollment exceptions in its README; verify examples typecheck against the exported APIs and add the wallet-core minor changeset entry.

## 2. Wallet-kit configuration and custom wallet integration

- [ ] 2.1 Extend RawWalletConfig and WalletConfig with the optional preference and normalize/validate it. Add config tests for omission, both supported values, invalid input, manually constructed legacy configs, and scalar/multi-chain parity; run wallet-kit tests and typecheck.
- [ ] 2.2 Pass the setting to shared injection and every per-chain provider. Extend runtime and controller tests to verify two-chain propagation, sign-in after restored session, management authorization, and explicit enrollment exceptions.
- [ ] 2.3 Prove application request fields cannot override preference through host/request tests, and that no new authenticator metadata is returned. Document the custom-wallet setting and guidance expectations in the kit README and add its minor changeset entry.

## 3. Stock wallet configuration and user guidance

- [ ] 3.1 Add GIANO_PASSKEY_DEVICE_PREFERENCE to the stock wallet entrypoint and both config templates, with browser-default as the default. Verify rendered config for unset, valid, invalid, scalar, and multi-chain cases, including the explicit multi-chain substitution allow-list; retain the hardened-image tool constraints.
- [ ] 3.2 Support the same setting in local development through Vite's served config path, without editing tracked defaults per run. Verify local config resolves the same values as the container and document the exact startup command in the developer guide.
- [ ] 3.3 Add shared conditional guidance near connect, signing approvals, and management sign-in. Add view/browser assertions for enabled versus default mode and ensure enrollment still says to use the current device; verify keyboard access and existing consent/sponsorship gating.
- [ ] 3.4 Document stock wallet runtime configuration, browser-controlled choice, rollback, and the dApp/wallet boundary in integration documentation. Verify sample configuration matches the templates and does not require a connector option or dependency upgrade.

## 4. Integration verification

- [ ] 4.1 Rebuild/recreate the E2E stack from the implementation checkout and verify readiness before testing. Exercise default and prefer-mobile modes with stock and BYO wallets, capture actual credential request options, and complete registration, restored-session signing, a sponsored transaction, and owner management; verify enrollment exceptions and no extra ceremonies.
- [ ] 4.2 Exercise the published-connector example demo against the configured stock wallet without changing its connector pin. Verify Setup verified, connection, signing, cancellation, and explanatory wallet copy; distinguish request-option assertions from native chooser behavior.
- [ ] 4.3 Record a real desktop-browser/phone smoke test for registration and signing, plus local-credential fallback and a browser/OS that ignores hints where available. State browser/OS versions and any unavailable hardware coverage; do not count virtual-authenticator success as proof of a phone chooser.
- [ ] 4.4 Run pnpm lint, wallet-core and wallet-kit tests/typechecks, wallet-web typecheck/build, relevant E2E suites, and openspec validate prefer-mobile-passkeys --strict. Verify changesets cover published API additions and no contract, credential-eligibility, lockfile, or default deployment behavior changes appear in the diff.

## Workflow follow-up

- Request implementation explicitly with openspec-apply-change; this proposal does not authorize code changes.
- Keep the implementation on the dedicated branch stacked above PR #176; update this PR when implementation is requested.
- After implementation and required review/checks, sync the delta spec and archive the completed change.
