
### Suggest using a phone

Set `passkeyDevicePreference: "prefer-mobile"` in the raw wallet config passed to
`resolveWalletConfig`, or in your custom `WalletConfig`. The kit passes it to the
shared API injection and every chain's provider. Omission or `"browser-default"`
retains the existing browser chooser. Unsupported values fail validation.

This is owned by the wallet deployment; an integrating dApp cannot override it
through the connector, request payload, or popup URL. Explain to users that the
browser may offer a phone/QR flow and that another available passkey can still
be selected. It is a suggestion, not a phone-only policy. Explicit current-device
and claim-device enrollment omits the suggestion for the new credential.
