## Purpose

Defines what the wallet shows to tell passkeys apart, and how a user signs in on the wallet origin.

## ADDED Requirements

### Requirement: The device and browser a passkey was added from are recorded
wallet-api SHALL record the device family and browser of the request that created a passkey, at registration and at the deposit of a passkey from another device, and SHALL carry them onto the bound credential. They SHALL be display only.

#### Scenario: A passkey added from an iPhone
- **WHEN** a second device using Safari on an iPhone deposits its passkey
- **THEN** the authorising device's consent and the owner list show it as "iPhone · Safari"

#### Scenario: Recorded before this change
- **WHEN** a passkey has no recorded device
- **THEN** the list shows it without one

### Requirement: A passkey from another device is named after where it was created
The authorising device's consent SHALL default the new passkey's name to the device and browser it was created on, when known.

#### Scenario: Default name
- **WHEN** the authorising device approves a passkey created on an iPhone with Safari
- **THEN** the passkey's name defaults to "iPhone · Safari"

### Requirement: One discoverable sign-in on the wallet origin
The wallet origin SHALL offer a single sign-in that lets the browser list every passkey the device holds for it, and SHALL sign in to the wallet the chosen passkey is bound to.

#### Scenario: A passkey added from another device
- **WHEN** a device signs in with a passkey it created through a claim
- **THEN** it signs in to the wallet that passkey joined, through the same sign-in as any other passkey
