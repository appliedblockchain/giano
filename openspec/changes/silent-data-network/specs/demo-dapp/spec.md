# Spec Delta

## ADDED Requirements

### Requirement: Private token section
When the selected chain's configuration names a `privateToken`, the demo SHALL show a private token section. The section SHALL read the connected wallet's balance of that token with an RPC request signed for the wallet, and SHALL provide mint and transfer controls that go through the wallet. For a chain without `privateToken`, the section SHALL NOT appear.

#### Scenario: Chain without a private token
- **WHEN** the selected chain's configuration has no `privateToken`
- **THEN** the private token section is not shown, and every other section works as before

#### Scenario: Signed balance read
- **WHEN** the user reads the private token balance on a chain that names one
- **THEN** the demo shows the wallet's balance, and the ledger records a signed read with the wallet's address as the reader

#### Scenario: Mint and transfer
- **WHEN** the user mints an amount, then transfers part of it to another address
- **THEN** each receipt is recorded, and the signed balance read after each step changes by the amount of that step

### Requirement: Signed reads ask for one passkey approval per session
The demo SHALL authorise signed reads with a delegate: the wallet approves one short-lived delegate key, and that key signs each read. Signed reads SHALL need at most one passkey prompt per chain and connected session until the delegate expires, and the delegate SHALL expire at most 1 hour after approval.

#### Scenario: Repeated reads
- **WHEN** the user reads the private balance three times in one session
- **THEN** exactly one passkey prompt occurred, before the first read

#### Scenario: Delegate expired
- **WHEN** the user reads the balance after the delegate has expired
- **THEN** the demo asks for one new approval, and the ledger records that the delegate was renewed

### Requirement: The section shows what an outsider sees
The private token section SHALL show the privacy properties next to the signed results. It SHALL show the result of the same balance read sent without a signature, and of a read for another address. It SHALL also show the latest transfer's bundle transaction as read by an unsigned request. The ledger SHALL record a successful outsider read of a balance as a privacy violation.

#### Scenario: Unsigned balance read
- **WHEN** the demo sends the balance read without a signature
- **THEN** the section shows that the read was refused, with the RPC's error, and no balance

#### Scenario: Another account's balance
- **WHEN** the demo reads, signed for the wallet, the balance of an address that is not the wallet
- **THEN** the section shows that the read was refused

#### Scenario: Transaction details hidden
- **WHEN** the demo reads the latest transfer's bundle transaction without a signature
- **THEN** the section shows its calldata, sender and value as the RPC's placeholders, not the real values

#### Scenario: Privacy violation
- **WHEN** an unsigned read, or a read for another address, returns a balance
- **THEN** the section shows a violation banner, the ledger records it with the chain and token, and the banner is not dismissed automatically
