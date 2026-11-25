## Purpose

Defines what the wallet records and shows about where each passkey is stored, and that it never decides anything.

## ADDED Requirements

### Requirement: Storage is recorded from the authenticator's own data
wallet-api SHALL record the AAGUID, the credential device type and the backup state that the authenticator reports, at registration and when a passkey is deposited into a pending addition, and SHALL carry them onto the credential row bound from that addition. It SHALL refresh the device type and backup state at each successful sign-in.

#### Scenario: A synced passkey is registered
- **WHEN** a passkey whose authenticator reports backup-eligible and backed up is registered
- **THEN** its credential lists `synced: true` and `deviceType: multiDevice`

#### Scenario: A passkey added from another device
- **WHEN** a passkey deposited from a second device is bound to the wallet
- **THEN** its credential lists the storage the second device's authenticator reported

#### Scenario: A passkey starts syncing
- **WHEN** a sign-in reports a backup state different from the recorded one
- **THEN** the recorded backup state follows the sign-in

### Requirement: The provider is named only when it is known
The provider name SHALL come from a fixed table of known AAGUIDs. An unknown AAGUID, the all-zero AAGUID, or a credential recorded before this change SHALL yield no provider name.

#### Scenario: Unknown provider
- **WHEN** a passkey's AAGUID is not in the table
- **THEN** the wallet shows whether it is synced, without a provider name

#### Scenario: Recorded before this change
- **WHEN** a credential has no recorded storage
- **THEN** the wallet says where it is stored was not recorded

### Requirement: Storage is display only
Storage SHALL NOT be an input to authentication, authorisation, sponsorship, owner matching or any other decision.

#### Scenario: A misreported AAGUID
- **WHEN** an authenticator reports another provider's AAGUID
- **THEN** only the label is wrong; nothing the passkey may do changes

### Requirement: Every passkey shows where it is stored
The stock wallet's management list SHALL show, for each passkey with a registry row, where it is stored. The bring-your-own reference SHALL show it too.

#### Scenario: Two devices
- **WHEN** a wallet holds a device-only passkey and a synced passkey from a second device
- **THEN** both devices list both passkeys, one as "This device only" and one as "Synced"
