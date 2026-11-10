## Purpose

Defines the timelock-aware checks the SDK's `assessHealth` and `giano-doctor chain` both apply: that the timelock alone holds the timelocked roles, that its delays are at or above the published values, and that the paymaster's implementation is a contracts release.

## ADDED Requirements

### Requirement: Health checks know about the timelock
`assessHealth` SHALL accept an optional timelock context: the timelock's address, its function delays as read from it, and the expected delays from the deployment's profile.

Without a timelock context, the timelocked-roles and delays checks SHALL report that no timelock is configured, as a warning, instead of the current "verify this is the timelock" warning for every single holder.

`giano-doctor chain` SHALL run the same checks with the same thresholds.

#### Scenario: No timelock context
- **WHEN** `assessHealth` is given no timelock context
- **THEN** the timelock checks warn that no timelock is configured, and no warning asks to verify each holder

### Requirement: The timelock alone holds the timelocked roles
Given a timelock context, `assessHealth` SHALL check:

| Check | Pass | Otherwise |
| --- | --- | --- |
| Timelocked roles held by the timelock only | `ROLE_ADMIN`, `UPGRADER_ROLE`, `FEE_ADMIN_ROLE` and `WITHDRAW_ADDRESS_ADMIN_ROLE` are each held by the timelock and nothing else | fail, naming each other holder |

#### Scenario: Timelock holds every timelocked role
- **WHEN** the timelock is the only holder of the four timelocked roles
- **THEN** the check passes, and no warning asks to verify the holder

#### Scenario: Extra holder
- **WHEN** an EOA holds `FEE_ADMIN_ROLE` beside the timelock
- **THEN** the check fails and names the EOA

### Requirement: Timelock delays are at or above the published values
Given a timelock context, `assessHealth` SHALL check:

| Check | Pass | Otherwise |
| --- | --- | --- |
| Delays at or above the published values | every function delay and the minimum delay are at least the profile's | fail, naming each short delay and its expected value |

A delay the expected values leave out SHALL NOT pass as at or above its published value: the delay check SHALL warn, naming each one.

#### Scenario: Delay below the profile
- **WHEN** the `upgradeToAndCall` delay is 1 day and the profile says 7 days
- **THEN** the delay check fails, naming `upgradeToAndCall`, 1 day and 7 days

#### Scenario: Delay with no published value
- **WHEN** the expected delays give only `minDelay`
- **THEN** the delay check warns, naming every other delay as having no published value

### Requirement: The implementation is matched to a release
Given the code at the implementation, `assessHealth` SHALL report which release's `GianoPaymaster` it is, by the release fingerprints (`releaseOf`). An implementation that matches no release SHALL fail the check, naming the newest release the SDK knows, so code from a newer release reads as an SDK to update rather than as unreviewed code.

#### Scenario: Current release
- **WHEN** the implementation's code matches release v2's fingerprint
- **THEN** the check passes and reads *release v2*

#### Scenario: Unknown code
- **WHEN** the implementation's code matches no release's fingerprint
- **THEN** the check fails, giving the implementation address and its codehash
