# Spec Delta

## MODIFIED Requirements

### Requirement: Chain list configuration
The container SHALL accept `GIANO_CHAINS` as a JSON array of `{ chainId, name, rpcUrl, explorerUrl?, defaultToken?, privateToken? }`.
`privateToken` is the address of a token whose balances only the holder can read; when present, the demo shows its
private token section for that chain.
For one release it SHALL also accept the scalar pair `GIANO_CHAIN_ID` / `GIANO_CHAIN_B_ID` (with names, RPC URLs and
`GIANO_TEST_ERC20`), converting it to the list form and logging a deprecation line. Supplying both SHALL fail start-up.

#### Scenario: JSON list
- **WHEN** `GIANO_CHAINS` names three chains
- **THEN** the selector offers all three in that order

#### Scenario: Legacy scalars
- **WHEN** only `GIANO_CHAIN_ID` and friends are set
- **THEN** the demo behaves as with an equivalent `GIANO_CHAINS` and the start-up log says the scalars are deprecated

#### Scenario: Invalid configuration
- **WHEN** `GIANO_CHAINS` is not a JSON array, or both it and the scalar pair are set
- **THEN** the container exits non-zero with the problem named, before serving anything

#### Scenario: Incomplete chain entry
- **WHEN** `GIANO_CHAINS` is a JSON array but a chain lacks `rpcUrl` or has an invalid field
- **THEN** the container serves the page and the browser renders the configuration-error screen naming the field
  (the container has no JSON parser; field validation is the browser's)

#### Scenario: Private token named
- **WHEN** a chain entry sets `privateToken` to an address
- **THEN** the demo shows the private token section for that chain, and no other chain shows it

#### Scenario: Invalid private token
- **WHEN** a chain entry sets `privateToken` to a value that is not an address
- **THEN** the browser renders the configuration-error screen naming `privateToken`
