# Proposal

## Why

Giano currently leaves the passkey chooser entirely to the browser, with no way for a wallet operator to suggest using a phone. An opt-in preference would help desktop users discover cross-device authentication while retaining local passkeys, security keys, and browsers that ignore the suggestion.

## What Changes

- Add an optional wallet-owned passkey preference: `browser-default` (the default) or `prefer-mobile`.
- Apply the preference consistently to new wallet registration, existing-passkey sign-in, restored sessions, message and transaction signing, and wallet-management authorization.
- Expose the setting through wallet-core APIs, wallet-kit configuration, and the stock wallet's runtime configuration. The integrating dApp does not control the setting through connector options or transport messages.
- Use WebAuthn `hints: ["hybrid"]` as a suggestion, without restricting authenticator attachment or credential transports. Preserve required user verification and existing consent gates.
- Provide brief wallet-side guidance that the browser may offer a phone or QR flow and that another available passkey can still be used.
- Preserve explicitly local passkey-addition and claim-device enrollment flows without a hybrid preference, so a user enrolling a phone does not get directed to a second phone.

## Capabilities

### New Capabilities

- `passkey-device-preference`: Wallet-owned device suggestions, ceremony coverage, compatibility, and user guidance.

### Modified Capabilities

None. Existing wallet-transaction-review consent requirements and tenant/origin isolation remain unchanged. No existing capability covers device selection preferences.

## Impact

Implementation will touch `packages/wallet-core`, `packages/wallet-kit`, `services/wallet-web`, their tests, stock wallet configuration templates, and wallet integration/developer documentation. Test coverage will include the BYO wallet and example demo through the E2E stack. Published wallet-core and wallet-kit API additions need a changeset when implemented. No backend schema, smart-contract, address, connector protocol, dependency upgrade, or production rollout change is proposed.

This planning PR is stacked on #176. Implementation requires a separate apply request.
