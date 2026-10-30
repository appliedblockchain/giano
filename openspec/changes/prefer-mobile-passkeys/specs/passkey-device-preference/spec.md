## Purpose

Defines how a wallet suggests a mobile authenticator while retaining browser choice, credential compatibility, consent, and wallet ownership of passkey ceremonies.

## ADDED Requirements

### Requirement: Preference belongs to the wallet deployment
A wallet SHALL accept an optional passkey device preference of `browser-default` or `prefer-mobile`. Omission SHALL select `browser-default`. An invalid configured value SHALL fail configuration validation with a message naming the setting. The SDK SHALL make this preference available to custom wallet implementations.

#### Scenario: Existing deployment
- **WHEN** an existing wallet deployment omits the preference
- **THEN** its passkey device selection behavior remains unchanged

#### Scenario: Invalid value
- **WHEN** a wallet configures an unsupported preference
- **THEN** it reports the configuration error before initiating a passkey ceremony

#### Scenario: Custom wallet
- **WHEN** a custom wallet selects `prefer-mobile` through the SDK
- **THEN** its eligible passkey ceremonies receive the same suggestion as the stock wallet

### Requirement: Integrating applications cannot override wallet preference
The wallet SHALL resolve device preference from its own configuration. Connector options, popup URLs supplied by an integrating application, and transport request payloads SHALL NOT override it or expose which authenticator the user selected.

#### Scenario: Application supplies an override
- **WHEN** an application includes a purported device preference in a connection or signing request
- **THEN** it cannot change the wallet's configured preference or obtain new authenticator metadata

### Requirement: Phone preference is advisory
For eligible ceremonies in `prefer-mobile` mode, the wallet SHALL request the WebAuthn `hybrid` hint. In `browser-default` mode it SHALL omit device hints. The preference SHALL NOT impose authenticator attachment constraints or narrow credential transports or eligible credential IDs.

#### Scenario: Desktop with a phone
- **WHEN** an eligible passkey ceremony begins with `prefer-mobile` enabled
- **THEN** its WebAuthn options contain `hints: ["hybrid"]` while the browser controls the chooser

#### Scenario: Browser ignores hints
- **WHEN** the browser ignores the hint or a phone is unavailable
- **THEN** the wallet accepts any otherwise valid eligible credential without requiring evidence of mobile use

### Requirement: Preference covers authentication and approval paths
The wallet SHALL apply its preference to initial registration, existing-passkey sign-in, and passkey signatures for transactions, messages, typed data, raw user operations, and owner management. Restoring a session SHALL retain the preference for later signatures without creating an additional ceremony during restore.

#### Scenario: Restored session signs
- **WHEN** a session is restored and the user later approves a transaction
- **THEN** the signing ceremony carries the configured suggestion and session restore itself raises no passkey prompt

#### Scenario: Multiple chains and management
- **WHEN** a wallet authorizes an owner change on multiple chains
- **THEN** each required signature carries the wallet preference with no additional preference-only ceremony

#### Scenario: Registration and existing passkey
- **WHEN** a user creates a wallet or signs in with an existing passkey under `prefer-mobile`
- **THEN** the applicable registration or authentication request carries the hybrid suggestion

### Requirement: Explicit enrollment remains on the intended device
Creating a passkey through an explicitly current-device addition or a claim-device enrollment SHALL omit the hybrid preference. This exception SHALL apply only to the new credential's registration; authorizing signatures from an existing owner SHALL continue using the wallet preference.

#### Scenario: Phone claims an addition
- **WHEN** the user opens a claim flow on the phone intended to hold the new passkey
- **THEN** registration does not suggest using another device and the existing fingerprint confirmation remains required

#### Scenario: Same-device addition
- **WHEN** the user chooses to add a passkey on the current device
- **THEN** its registration has no hybrid hint and subsequent owner authorization follows the configured preference

### Requirement: Preference preserves security and cancellation semantics
Device preference SHALL preserve required user verification, relying-party scope, eligible credential IDs, challenge data, and existing consent and sponsorship gates. A cancellation SHALL follow existing cancellation behavior, without an automatic retry that opens a second ceremony or weakens verification.

#### Scenario: Cancel phone chooser
- **WHEN** the user cancels a passkey prompt in `prefer-mobile` mode
- **THEN** the wallet follows its existing cancellation path without silently trying a different authenticator

#### Scenario: Unsponsored transaction refused
- **WHEN** sponsorship or another existing consent prerequisite refuses a transaction
- **THEN** phone preference does not trigger a passkey prompt or bypass the refusal

### Requirement: Wallet guidance explains the suggestion accurately
With `prefer-mobile` enabled, the stock wallet SHALL offer brief guidance near passkey actions explaining the possible phone or QR flow and the availability of other eligible passkeys. It SHALL NOT claim that a phone was used, is mandatory, or stores the passkey exclusively. Default mode SHALL retain existing guidance.

#### Scenario: Browser has its own chooser
- **WHEN** the stock wallet displays a passkey action in phone-preference mode
- **THEN** its guidance describes the browser-controlled choice without promising a particular chooser or outcome

### Requirement: Runtime configuration works across deployment shapes
The stock wallet SHALL accept the preference through its runtime configuration in both single-chain and multi-chain deployments, without rebuilding the frontend. Local development and custom wallet configuration SHALL support the same values and default.

#### Scenario: Operator enables preference
- **WHEN** an operator sets `prefer-mobile` and starts the stock wallet with either supported chain configuration shape
- **THEN** its served configuration resolves the preference consistently across all served chains
