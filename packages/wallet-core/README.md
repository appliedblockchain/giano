
### Suggest using a phone

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
