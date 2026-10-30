# G4: WebAuthn user verification

Decision record for Notion item **G4: Decide whether WebAuthn user verification can be enforced,
or document why not** (production-readiness gap report, item B4).

**Decision (28 October 2026): Giano requires user verification at both verifiers.** It is
implemented in PR #170, stacked on #169. The newcomer-friendly report with the same evidence is the
[G4 report artifact](https://claude.ai/artifact/KDXpKqiifSnZTCpjA3ecEa).

The investigation ran against `feat/entrypoint-v09` (PR #169, commit `2c16094`). Sections R1 to R3
describe the code **before** this change, which is why they say "not enforced".

## What changed

| Where | Change |
| --- | --- |
| `packages/contracts/src/GianoSmartWallet.sol` | `requireUV: true`. Release v2 re-cut (`releases/v2/*`), `canonical.ts` code hashes regenerated, both devnet states regenerated with the pinned anvil. Canonical addresses and `e2e/devnet/addresses.json` are unchanged. |
| `packages/contracts/test/GianoSmartWallet/UserVerification.t.sol` | New: UP+UV accepted; UP only, no flags and UV without UP rejected, through `isValidSignature` and `validateUserOp`. |
| `services/wallet-api/src/routes/webauthn.ts`, `wallet-management.ts` | `requireUserVerification: true` at registration, sign-in and claim/fill. |
| `services/wallet-api/test/` | Fixtures take a `flags` option. New tests: a UP-only registration, sign-in and claim/fill are each refused with `verification-failed`; a refused fill leaves the slot open. |
| `packages/wallet-core` | `BaseCredentialInfo.userVerification` is typed `'required'`. `'preferred'` and `'discouraged'` are refused by validation (major changeset). |
| Specs and docs | BR-37, `specs/ARCHITECTURE.md` §6, `specs/INTEGRATION.md` ("Passkeys and user verification"), `docs/ENTRYPOINT-V09-UPGRADE.md`. |

Release v2 was re-cut rather than a v3 cut. v2 exists only in the unmerged #169 and was never
deployed to a public chain, and a v3 would have left v2 as a canonical release that new wallets on
some chain could be born on without the check.

## Decision

| Layer | Decision | Why |
| --- | --- | --- |
| wallet-api (registration, sign-in, wallet-management claim) | **Enforce UV** (`requireUserVerification: true`) | Every genuine Giano client already asks for `'required'`, so a compliant platform either returns UV=1 or fails before the request reaches the server. All wallet-api tests pass with enforcement on, plus new tests that UP-only responses are refused. It is also `@simplewebauthn/server`'s default; Giano turns it off explicitly. |
| `GianoSmartWallet` (UserOperations, ERC-1271 messages, `signedStaticCall`) | **Enforce UV** (`requireUV: true`), shipped in contract release **v2**, before PR #169's release reaches any public chain | This is the only layer that protects assets (BR-02: the backend can never authorise a transaction). All Foundry tests pass with the flag on, 185 including the new UV tests. Wallet addresses do not change, because canonical addresses come from CREATE3 labels rather than bytecode. No public chain holds a Giano deployment yet, so there are no wallets to migrate. |

Residual risk that enforcement cannot remove: some third-party passkey managers report UV=1 without
verifying anyone. The passkeys.dev known-issues list names the 1Password and Bitwarden browser
extensions, KeePassXC, Proton Pass and Strongbox. That risk needs a named owner to accept it (R5).

## Background

Every WebAuthn signature covers `authenticatorData`. Byte 32 of that structure holds flags:

| Bit | Mask | Name | Meaning |
| --- | --- | --- | --- |
| 0 | `0x01` | UP, user present | Someone touched or approved the authenticator. |
| 2 | `0x04` | UV, user verified | The authenticator checked who that person is, with a PIN, biometric or device passcode. |

The relying party *asks* for UV through `userVerification: 'required' | 'preferred' | 'discouraged'`.
Only the party that verifies the signature can *require* it, by rejecting a signature whose UV bit is 0.
The browser is not a security boundary here. A modified client, a script, or a tool that talks CTAP
directly to a security key can ask for `'discouraged'` and obtain a valid UP-only signature.

Giano has two verifiers:

- **wallet-api** verifies registration and sign-in ceremonies with `@simplewebauthn/server`. A
  successful sign-in yields a session token.
- **The wallet contract** verifies every UserOperation and ERC-1271 signature on chain with
  `webauthn-sol`. Anyone can submit a signed operation to the EntryPoint without going through
  wallet-api, so this is the only check that guards funds.

## R1: what Giano asks for and enforces today

| Path | What the client asks for | Enforced by wallet-api? | Enforced on chain? |
| --- | --- | --- | --- |
| Create passkey (connect) | `'required'`: `wallet-core/src/provider.ts:560-577`, default from `provider-injection/types/credential-info/defaults.ts:14` | No: `wallet-api/src/routes/webauthn.ts:304` | n/a |
| Sign in with existing passkey | `'required'`: `wallet-core/src/provider-injection/wallet-api/create-wallet-api-injection.ts:157` | No: `webauthn.ts:504` | n/a |
| Credential lookup (`getCredential`) | `'required'` default: `wallet-core/src/account/get-credential.ts:28-29` | (same as sign-in) | n/a |
| Add a passkey (wallet-management claim) | `'required'`: `wallet-core/src/management/create-passkey.ts:47` | No: `wallet-api/src/routes/wallet-management.ts:607` | The owner is then added on chain by an existing owner's signature (below). |
| Sign UserOperation / message / typed data / `signed_eth_call` | `'required'`: viem `toWebAuthnAccount` passes no `userVerification`, so ox `WebAuthnP256.sign` defaults to `'required'` (ox 0.14.57 `webauthn/Authentication.ts:168`) | Not verified by wallet-api at all; the relay forwards the operation | No: `packages/contracts/src/GianoSmartWallet.sol:343` passes `requireUV: false` |
| Platform-admin sign-in | n/a: EOA SIWE (`services/platform-sessions.ts`) | n/a | n/a |

Two further facts:

- `BaseCredentialInfo.userVerification` (`provider-injection/types/credential-info/base-credential-info.ts:14`)
  is a public option. A bring-your-own wallet integration can pass `'preferred'` or `'discouraged'`.
  The stock wallet-api injection never does.
- The Notion item cites `webauthn.ts:224/359` and `wallet-management.ts:461`. Those were `main`'s
  lines; on this branch they are `304`, `504` and `607`.

## Experiments

All experiments ran in a throwaway worktree. Nothing from them is committed.

**Contract probe.** A Foundry test signed the same message three times with a P-256 owner key,
changing only the flags byte, and called `isValidSignature`:

| Flags | Today (`requireUV: false`) | With `requireUV: true` |
| --- | --- | --- |
| `0x05` UP+UV | accepted | accepted |
| `0x01` UP only | **accepted** | rejected |
| `0x00` none | rejected | rejected |

- Full Foundry suite with `requireUV: true`: 181 of 181 pass (180 existing tests and the probe).
  Every existing passkey fixture already uses flags `0x05`, from `webauthn-sol/test/Utils.sol`.
- Cost: an accepted passkey signature went from 362,386 to 362,529 gas, **+143 gas**, in the
  test environment. That environment has no RIP-7212 precompile, so the total includes the FCL
  software verifier, but the delta is only the extra flag check. Runtime size went from
  12,356 to 12,385 bytes, **+29 bytes**.

**Backend.** With all three `requireUserVerification` flags set to `true`, all 21 wallet-api
test files and all 406 tests pass. The fixtures already sign with `0x45` (UP|UV|AT) for
registration and `0x05` for authentication (`services/wallet-api/test/webauthn-fixtures.ts:103,162`).
No test today proves that a UV=0 response is rejected.

**E2E (not run).** The Playwright virtual authenticator is created with
`hasUserVerification: true, isUserVerified: true` (`e2e/tests/helpers.ts:100-101`), so it produces
UV=1. Enforcement should not affect the suite. This was inferred from the code, not executed.

## Threat model

| Threat | Backend enforcement | Contract enforcement |
| --- | --- | --- |
| Someone holding a lost or stolen FIDO2 security key, without its PIN, talks CTAP directly to it with `uv` discouraged | Blocks a session. A session alone cannot move assets. | **Blocks asset movement.** Today a UP-only signature from the key controls the wallet: webauthn-sol skips the origin check, so any client can build `clientDataJSON`. Depending on the key's credProtect policy the attacker may also need the credential ID. That is not secret: wallet-api returns it from `/v1/webauthn/options` on open-registration tenants. |
| Malware or a hostile page tricks the user into a touch-only approval on a plugged-in security key | Blocks a session | Blocks the operation, unless the attacker also obtains the PIN |
| Modified client or direct API call presenting a UP-only assertion | Blocks | Blocks |
| Platform passkeys (iCloud Keychain, Google Password Manager, Windows Hello, hybrid QR) | No change: these verify the user when asked for `'required'` | No change |
| Third-party passkey manager that sets UV=1 without verifying | **Not addressed.** The flag is self-reported and these managers do not verify. | **Not addressed** |
| Malware on an unlocked device that persuades the user to approve a biometric prompt | Not addressed | Not addressed. That needs transaction-display and consent controls, which are a separate concern. |

What a UP-only *session* can do today: relay operations (each still needs a valid on-chain owner
signature), request sponsorship data for them, read owner events, and open, complete or decline
pending owner additions (adding the owner still needs an on-chain owner signature). Backend
enforcement therefore matters mainly for hygiene, for spec conformance (WebAuthn L3 §7.1 step 16,
§7.2 step 17), and as a **prerequisite for contract enforcement** (next section).

### Why the backend must enforce before, or together with, the contract

A wallet address is derived when a passkey is registered, before any on-chain signature exists. If
wallet-api registered a credential that cannot perform UV, and the contract then required UV, that
owner could never sign. If it were the only owner, any funds sent to the counterfactual address
would be stuck. Enforcing UV at registration and at wallet-management claim stops a UV-incapable
credential from entering the system through Giano's own flows. Owners added directly on chain
(`addOwnerPublicKey`) bypass wallet-api, and remain the integrator's responsibility.

## R2: backend feasibility

**Feasible.** Since the client always asks for `'required'`, the spec obliges the client to fail if
it cannot verify the user ("The client MUST return an error if user verification cannot be
performed", WebAuthn L3 §5.8.6). Enforcement changes only *where* a non-verifying authenticator
fails: on the server instead of in the browser. For a genuine client it should never trigger.

Expected behaviour from desk research. **No physical-device test has been run.**

| Platform | With `'required'` | Source and confidence |
| --- | --- | --- |
| iOS / macOS Safari, iCloud Keychain | UV=1; falls back to the device passcode or system password when there is no biometric | passkeys.dev macOS reference. Verified. |
| Chrome on iOS, iCloud Keychain via autofill | UV=0 bug, now fixed (iOS 26.5.2 with Chrome 151, per the reporter) | Apple forums thread 813784, FB21756948 |
| Apple "automatic passkey upgrade" (conditional create) | UP=0, UV=0 by design | FIDO dev list. Giano does not use conditional create. |
| Android Chrome, Google Password Manager | Screen lock is required to use passkeys | developer.chrome.com. No UV=0 case found. Behaviour on a device with no screen lock was not verified. |
| Desktop Chrome, Google Password Manager | GPM PIN is set on first save | developer.chrome.com |
| Windows Hello | UV on each operation | Third-party source (Corbado). No Microsoft statement found. |
| Cross-device QR (hybrid) | The phone performs UV | General spec rule. No flow-specific source found. |
| FIDO2 key with a PIN set (YubiKey 5) | UV=1 | Yubico |
| FIDO2 key without a PIN | Chrome prompts the user to set one. Firefox ignores the key. iOS Safari does not prompt, so it fails. | python-fido2 #162, Mozilla 1854089, Yubico iOS known issues |
| U2F-only key | Cannot do UV, so it is excluded already today | WebKit 215836 |
| 1Password / Bitwarden extensions, KeePassXC, Proton Pass, Strongbox | Report UV=1 **without verifying** | passkeys.dev known issues (updated 2026-04-09) |

Nothing on this list returns UV=0 to a genuine Giano client today and still succeeds, except
already-fixed browser bugs. So enforcement excludes no authenticator that currently works.

**Recommended rollout.**

1. *Shadow mode.* Keep `false`, but record `registrationInfo.userVerified` and
   `authenticationInfo.userVerified` (both already returned by `@simplewebauthn/server`) as a
   per-tenant metric on dev and testnets. The device matrix is then measured, not assumed.
2. Run the R2 matrix on real devices, using the shadow metric to read the flag.
3. Flip the three call sites to `true` and add negative tests: a UV=0 registration, a UV=0
   authentication and a UV=0 claim fill each return `verification-failed`.
4. Narrow or remove the `BaseCredentialInfo.userVerification` override, so an integrator cannot ask
   for `'preferred'` and then be refused by the server.

## R3: contract feasibility

**Feasible and cheap now.** It gets expensive only if it waits until after a public deployment.

- **Addresses.** Canonical addresses are CREATE3 addresses: a function of the deployer EOA and a
  fixed label (`packages/contracts/deploy/config.ts` `LABELS`, `deploy/create3.ts`), not of bytecode.
  The factory is constructed with the implementation's *label* address, and wallets derive from
  `initCodeHashERC1967(implementation)` (`GianoSmartWalletFactory.sol:16,57,81`). Changing the
  wallet's bytecode therefore changes **no** factory address, implementation address or user wallet
  address. The Notion item's concern that this would change "every future wallet address" does not
  apply to this deployment scheme. The old Ignition/CREATE2 scheme was bytecode-dependent; the
  CREATE3 scheme replaced it.
- **Existing wallets.** The public registry is empty and `CANONICAL_DEPLOYER` is still the
  `0x…dEaD` placeholder (`deploy/config.ts`), so no public chain has a canonical Giano deployment.
  The committed registry is empty on `main` too. The only live wallets are on local devnets and the
  dev environment, and they are test accounts. Re-check this before cutting the release if a
  testnet deployment has happened in the meantime.
- **Release v2.** PR #169 freezes contract release v2 with a new wallet implementation, because
  EntryPoint v0.9 already forces one. Adding `requireUV: true` before v2 is first deployed costs a
  re-cut of v2: `releases/v2/*`, canonical code hashes and both devnet states. It does not cost a
  migration.
- **If it lands later (v3).** On chains that already hold v2 at the fixed label, the new
  implementation deploys under `giano.wallet.impl@v3` (`upgradeLabel`). Each wallet must then be
  upgraded with an owner-signed `upgradeToAndCall`. Because `upgradeToAndCall` is allowed through
  `executeWithoutChainIdValidation` (`GianoSmartWallet.sol:277-288`), one signature can be replayed
  on every chain, since the `@v3` address is identical everywhere. The factory's implementation is
  immutable, though, so on those chains **new wallets would still be born on v2** without UV
  enforcement until they upgrade. That is the real cost of waiting.
- **Gas and size.** +143 gas per passkey verification and +29 bytes runtime (see Experiments).
- **Audit (report item T1).** The change is a single literal in the signature path, but it changes
  who can authorise. It should be in the audit scope, together with the v0.9 changes in v2.
- **Upgrade authority (report item C6).** Any single owner can upgrade. With UV enforced, a
  security-key owner needs the PIN to perform that upgrade too. Without it, a stolen key alone
  could upgrade the wallet to an arbitrary implementation.

### Coinbase parity

- Coinbase Smart Wallet passes `requireUV: false` with no comment, unchanged through v1.1.0
  (July 2025). Base's newer native-AA code also skips step 17 "as the deployed WebAuthnAuthenticator".
- No Coinbase source states why. None of the Cantina, Certora or Code4rena reports contain a
  UV finding.
- The most plausible reason: keys.coinbase.com reportedly asks for `'preferred'` (Corbado's
  review; the site is closed source, so this is unverified). webauthn-sol's own NatSpec says UV
  "should be required if, and only if, options.userVerification is set to required in the
  request". For a `'preferred'` client, `false` is the consistent choice.
- Giano always asks for `'required'`. By that same rule, Giano should pass `true`. The parity
  argument supports enforcement, not the current setting.

| Passkey account | Requires UV on chain? |
| --- | --- |
| Safe passkey module | Yes |
| ZeroDev Kernel WebAuthn validator | Yes |
| Clave | Yes (mask `0x05`) |
| OpenZeppelin 5.x `WebAuthn.verify` | Yes, by default |
| Coinbase Smart Wallet / Base | No |
| Alchemy Modular Account | No |
| Daimo | No |
| Porto (Ithaca) | No |

## R4: where the decision is recorded

Applied in PR #170, in this wording:

- **`specs/ARCHITECTURE.md`, §6 Isolation, new paragraph "User verification":** Every passkey
  ceremony asks for user verification, and both verifiers require it: wallet-api rejects
  registration, sign-in and owner-addition responses without the UV flag, and the wallet contract
  rejects any passkey signature without it. The contract check is the one that protects assets.
  The backend check keeps credentials that cannot verify the user out of the system, so that no
  wallet gains an owner it cannot use.
- **New requirement BR-37, `specs/BUSINESS-REQUIREMENTS.md` §2.1:** Every use of a
  passkey to sign MUST require user verification by the authenticator (PIN, biometric or device
  passcode). Presence alone MUST NOT be sufficient to authorise a transaction, sign a message, or
  open a session.
- **Integrator docs (`specs/INTEGRATION.md`, "Passkeys and user verification"):** state that U2F-only keys and FIDO2 keys without a
  PIN are unsupported, and that adding a passkey owner directly on chain is the integrator's
  responsibility to check.

## R5: residual risk

- **Not removed by enforcement:** passkey managers that report UV=1 without verifying, and
  approval of a malicious operation by a verified user. Compensating controls: the consent screen
  on the wallet origin, relay policy, and recovery and owner removal (BR-32/BR-33).
- **Optional defence in depth:** the wallet-api relay could decode the `SignatureWrapper` and refuse
  to forward a passkey signature whose UV bit is 0. That gives an earlier, clearer error, but
  direct EntryPoint submission bypasses it. It does not replace contract enforcement.
- **Risk owner:** to be named by the product owner. This record does not accept risk on anyone's
  behalf.

## Follow-up items

Done in PR #170: backend enforcement with negative tests, the `userVerification` override narrowed,
contract enforcement with release v2 re-cut and devnet states regenerated, a Foundry test that
rejects UP-only signatures, and the spec and integrator-doc updates (R4). The team chose to enforce
directly, without the shadow-metric phase.

Still open:

1. Run the R2 device matrix on real devices.
2. An e2e negative case with `isUserVerified: false` against the stack.
3. Risk sign-off (R5): a named owner for the residual risk.
4. Coordinate with G1 (registration identity binding), which edits the same `webauthn.ts` handlers.

## Not verified

- No physical device was tested. Windows Hello, Google Password Manager on a device without a
  screen lock, hybrid QR, Dashlane and Samsung Internet have no authoritative source.
- Whether a stolen PIN-less-use attack also needs the credential ID depends on the key's
  credProtect level. That was not tested.
- Coinbase's actual reasoning is undocumented.

## Sources

- WebAuthn Level 3: <https://www.w3.org/TR/webauthn-3/> (§5.8.6, §7.1 step 16, §7.2 step 17)
- passkeys.dev known issues: <https://passkeys.dev/docs/reference/known-issues/>
- passkeys.dev macOS reference: <https://passkeys.dev/docs/reference/macos/>
- web.dev on user verification: <https://web.dev/articles/webauthn-user-verification>
- Chrome GPM on desktop: <https://developer.chrome.com/blog/passkeys-gpm-desktop>
- Chrome on iOS autofill UV bug: <https://developer.apple.com/forums/thread/813784>
- YubiKey PIN behaviour: <https://github.com/Yubico/python-fido2/issues/162>, <https://bugzilla.mozilla.org/show_bug.cgi?id=1854089>
- Coinbase Smart Wallet: <https://github.com/coinbase/smart-wallet/blob/main/src/CoinbaseSmartWallet.sol>, audits in `audits/`
- Code4rena Coinbase report: <https://code4rena.com/reports/2024-03-coinbase>
- Corbado on keys.coinbase.com: <https://www.corbado.com/blog/smart-wallets-passkeys>
- webauthn-sol: <https://github.com/base/webauthn-sol/blob/main/src/WebAuthn.sol>
- OpenZeppelin WebAuthn: <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/WebAuthn.sol>
- Safe passkey module: <https://github.com/safe-global/safe-modules/tree/main/modules/passkey>
- ZeroDev: <https://github.com/zerodevapp/kernel-7579-plugins/blob/main/src/validators/WebAuthnValidator.sol>
