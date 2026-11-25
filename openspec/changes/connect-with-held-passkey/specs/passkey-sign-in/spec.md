## Purpose

Defines how a connect without a session signs in, so a device signs in with the passkey it holds rather than with the passkeys of the user its browser last knew, and how new passkeys are named.

## ADDED Requirements

### Requirement: A discoverable sign-in is bound to no user
wallet-api SHALL issue, on request, a sign-in challenge bound to no user, list no credentials with it, and accept any non-removed credential of the tenant against it. It SHALL refuse such a challenge for registration.

#### Scenario: The device last knew another user
- **WHEN** a device whose stored user is someone else signs in with a discoverable challenge
- **THEN** the session is for the passkey's own user and wallet

### Requirement: A device that holds a passkey signs in with it
When there is no session and the device is known to hold a passkey, approving a connect SHALL ask the browser for any passkey it holds for the wallet origin, and SHALL connect to the wallet the chosen passkey is bound to. The screen SHALL offer creating a new wallet instead.

#### Scenario: Straight to the application after joining
- **WHEN** a device that joined a wallet connects from an application without signing in on the wallet origin first
- **THEN** it connects to the wallet it joined, with the passkey it holds, and no passkey or wallet is created

#### Scenario: Create a new wallet
- **WHEN** the user chooses to create a new wallet on a device whose stored user already has one
- **THEN** a new passkey and wallet are created under a new external user id

### Requirement: A device that never signed in can still use a held passkey
When nothing is known about the device, approving a connect SHALL behave as before, and the screen SHALL offer signing in with a passkey the device holds.

#### Scenario: Returning user on a fresh browser
- **WHEN** a user whose passkey is synced to a fresh browser chooses to use a passkey they already have
- **THEN** they connect to their existing wallet

### Requirement: A session decides
With a session, a connect SHALL sign in with the session's credential and wallet, whatever choice or stored user applies.

#### Scenario: Session present
- **WHEN** a device with a session connects
- **THEN** no alternative is offered and the session's passkey signs

### Requirement: Passkeys are named so a picker can tell them apart
A passkey added to an existing wallet SHALL be named after that wallet, shortened; a first passkey SHALL be named after the day it was made.

#### Scenario: Passkey added from another device
- **WHEN** a second device creates its passkey through a claim
- **THEN** the passkey's name carries the joined wallet's shortened address
