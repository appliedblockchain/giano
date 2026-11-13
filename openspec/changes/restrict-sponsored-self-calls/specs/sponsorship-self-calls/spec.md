## ADDED Requirements

### Requirement: Only owner changes and a plain transfer to self are wallet management
The sponsorship rules SHALL treat a call whose target is the operation's sender as wallet management only when it is one of:
- a call to `addOwnerAddress`, `addOwnerPublicKey` or `removeOwnerAtIndex`, with a value of zero;
- a plain value transfer, with calldata of exactly `0x`, of any value.

#### Scenario: Plain transfer to self
- **WHEN** a user's operation is `execute(self, 0, 0x)`
- **THEN** the operation is sponsored as wallet management

### Requirement: Wallet management needs no allowlist entry
Wallet management SHALL be sponsored under the platform's wallet-management cap, or the tenant's lower one, without an entry in the tenant's allowlist, unless the tenant has set `walletManagement.enabled: false`.

#### Scenario: Adding a passkey
- **WHEN** a user's operation is `execute(self, 0, addOwnerPublicKey(x, y))` and nothing about the wallet is in the tenant's allowlist
- **THEN** the operation is sponsored, `isWalletManagement` is true, and the platform cap applies

### Requirement: Every other self-call is refused
The sponsorship rules SHALL refuse an operation that contains any other call whose target is the operation's sender, with reason `contract-not-allowed`. The decision table SHALL record the refusal under the rule `self-calls`. A refused self-call SHALL NOT count as wallet management, and SHALL NOT skip the allowlist.

#### Scenario: The refusal has its own rule
- **WHEN** a refused self-call decodes as `execute` or `executeBatch`
- **THEN** the `decodable-calls` rule passes and the `self-calls` rule fails

#### Scenario: Nested execute
- **WHEN** a user's operation is `execute(self, 0, execute(target, 0, data))`
- **THEN** the operation is refused with `contract-not-allowed`, the `self-calls` rule fails, and `isWalletManagement` is false

#### Scenario: Upgrade
- **WHEN** a user's operation is `execute(self, 0, upgradeToAndCall(impl, 0x))`
- **THEN** the operation is refused with `contract-not-allowed`

#### Scenario: Removing the last owner
- **WHEN** a user's operation is `execute(self, 0, removeLastOwner(0, owner))`
- **THEN** the operation is refused with `contract-not-allowed`

#### Scenario: Owner change with value
- **WHEN** a user's operation is `execute(self, 1, addOwnerAddress(a))`
- **THEN** the operation is refused with `contract-not-allowed`

#### Scenario: Mixed batch
- **WHEN** a batch contains an owner change and a nested `execute` to the wallet
- **THEN** the whole operation is refused
