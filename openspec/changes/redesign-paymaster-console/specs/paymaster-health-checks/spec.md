## ADDED Requirements

### Requirement: Health checks know about the timelock
`assessHealth` SHALL accept an optional timelock context: the timelock's address, its function delays as read from it, and the expected delays from the deployment's profile. Given one, it SHALL check:

| Check | Pass | Otherwise |
| --- | --- | --- |
| Timelocked roles held by the timelock only | `ROLE_ADMIN`, `UPGRADER_ROLE`, `FEE_ADMIN_ROLE` and `WITHDRAW_ADDRESS_ADMIN_ROLE` are each held by the timelock and nothing else | fail, naming each other holder |
| Delays at or above the published values | every function delay and the minimum delay are at least the profile's | fail, naming each short delay and its expected value |

Without a timelock context, these checks SHALL report that no timelock is configured, as a warning, instead of the current "verify this is the timelock" warning for every single holder.

`giano-doctor chain` SHALL run the same checks with the same thresholds.

#### Scenario: Timelock holds every timelocked role
- **WHEN** the timelock is the only holder of the four timelocked roles
- **THEN** the check passes, and no warning asks to verify the holder

#### Scenario: Extra holder
- **WHEN** an EOA holds `FEE_ADMIN_ROLE` beside the timelock
- **THEN** the check fails and names the EOA

#### Scenario: Delay below the profile
- **WHEN** the `upgradeToAndCall` delay is 1 day and the profile says 7 days
- **THEN** the delay check fails, naming `upgradeToAndCall`, 1 day and 7 days

### Requirement: The implementation is matched to a release
Each release in `packages/contracts/releases/` SHALL record the runtime codehash of `GianoPaymaster`. Given the implementation's runtime codehash, `assessHealth` SHALL report which release it matches. An implementation that matches no release SHALL fail the check.

#### Scenario: Current release
- **WHEN** the implementation's codehash equals release v2's
- **THEN** the check passes and reads *release v2*

#### Scenario: Unknown code
- **WHEN** the implementation's codehash matches no release
- **THEN** the check fails, giving the implementation address and its codehash
