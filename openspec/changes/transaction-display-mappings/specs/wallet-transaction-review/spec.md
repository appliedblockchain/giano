## Purpose

Defines what a wallet origin shows a user who is asked to approve a transaction: a human-readable account of the action first, the chain's own currency, and raw data only when nothing readable can be produced. Covers the kit-level description surface available to any wallet origin and the stock wallet's rendering of it.

## ADDED Requirements

### Requirement: The kit describes a transaction for its chain
Every per-chain wallet runtime SHALL offer a `describeTransaction` operation that takes the transaction request as received from the application and resolves to a description as defined by the `transaction-description` capability. It SHALL use the tenant's mappings for that chain fetched from the wallet service, merged with the library's built-in generic mappings, SHALL resolve token symbols and decimals through the runtime's own chain client, and SHALL name the chain's native currency from the chain's configuration (defaulting to ETH). It SHALL never reject: any failure degrades to a description with warnings, or to an unknown result.

#### Scenario: Tenant mapping applied
- **WHEN** the tenant has published a mapping for the target contract on the session's chain and the application sends a call it covers
- **THEN** the runtime resolves to a description whose source is the tenant mapping, with token amounts scaled and symbolled from chain reads

#### Scenario: Wallet service unreachable
- **WHEN** the mappings request fails or times out
- **THEN** the runtime still resolves, using built-ins only, and the description carries a warning that the application's mappings could not be loaded

#### Scenario: Token metadata read fails
- **WHEN** the token's `symbol` or `decimals` cannot be read within the timeout
- **THEN** the runtime still resolves, showing the unscaled amount with the token address and a warning

#### Scenario: Mappings are cached per runtime
- **WHEN** two transactions are reviewed on the same chain within the cache window
- **THEN** the mapping set is fetched once

#### Scenario: Available to bring-your-own origins
- **WHEN** a non-stock wallet origin built on the kit receives a transaction consent request
- **THEN** it can call `describeTransaction` on the request's runtime without talking to the wallet service itself

### Requirement: The review screen leads with the description
When the description is not unknown, the stock wallet's transaction review SHALL show, above everything else about the transaction: the intent sentence; the labelled fields in the mapping's order; the network name (already required by MC-80); the origin of the requesting application; and any native value in the chain's currency. Raw calldata SHALL NOT be shown for a described transaction; a collapsed "technical details" control MAY reveal contract address, function signature and calldata on demand.

#### Scenario: Described transaction
- **WHEN** the application requests an ERC-20 transfer covered by a mapping
- **THEN** the screen shows an intent such as "Send 10.5 USDC to 0x1234…abcd" and fields for amount and recipient, and shows no hex calldata by default

#### Scenario: Generic mapping is flagged
- **WHEN** the description's source is a built-in generic mapping
- **THEN** the screen shows the intent and a visible note that the wallet assumed a standard token interface for this contract and the application did not confirm it

#### Scenario: Native currency per chain
- **WHEN** the session's chain configures a native currency other than ETH
- **THEN** value fields use that currency's symbol, and "ETH" appears nowhere on the screen

### Requirement: Raw data is the last resort and is labelled as such
When the description is unknown, the review SHALL show a prominent warning that the wallet cannot explain what this transaction does, the reason in plain words (no mapping for this contract and function, malformed call, or contract creation), the contract address and selector when known, and the raw value and calldata. The approve action SHALL remain available, because refusing would block legitimate but unmapped applications, but the user SHALL have seen the warning before any approve control is offered.

#### Scenario: Unmapped contract call
- **WHEN** the application requests a call to a contract and selector with no mapping
- **THEN** the screen shows the "cannot explain this transaction" warning, the selector and contract, and the raw calldata, and no intent sentence

#### Scenario: Nothing readable is fabricated
- **WHEN** the description is unknown
- **THEN** the screen shows no decoded argument list or function name guessed from the calldata

### Requirement: Approval waits for the description and the sponsorship pre-flight
The approve control SHALL NOT be rendered until both the description has settled (described or unknown) and the sponsorship pre-flight has resolved as specified in WK-13 to WK-15. While the description is pending the screen SHALL indicate it is preparing the transaction summary.

#### Scenario: Description still loading
- **WHEN** the pre-flight has resolved as sponsored but the description has not settled
- **THEN** no approve control is shown and a loading indicator is

#### Scenario: Both settled
- **WHEN** the description has settled and the pre-flight permits approval
- **THEN** the approve control appears

### Requirement: The end-to-end suite proves the description path
The Playwright suite SHALL assert, for the demo ERC-20 transfer sent through the stock wallet, that the review shows an intent sentence naming a transfer and no raw calldata by default; and, for the bring-your-own wallet, that its own rendering of the intent appears.

#### Scenario: Stock wallet
- **WHEN** the e2e dApp sends the demo ERC-20 transfer
- **THEN** the stock wallet's review shows a transfer intent and the raw-calldata element is absent

#### Scenario: BYO wallet
- **WHEN** the same transfer is reviewed in the bring-your-own wallet origin
- **THEN** its intent element is present and non-empty
