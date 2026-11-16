## MODIFIED Requirements

### Requirement: Live-service keys are inventoried
The repository SHALL keep an inventory of every key that a live Giano deployment uses, in `docs/key-ceremony.md`. For
each key it SHALL give:
- its name;
- what it signs, or which role it holds;
- whether it is in ABIP-8 scope;
- the secret store that holds it in each environment class;
- which service consumes it.

The inventory SHALL include at least:
- the mainnet canonical deployer;
- the testnet canonical deployer;
- the sponsorship signer;
- the bundler executor;
- the paymaster `ROLE_ADMIN`, and the proposer and executor keys of the TimelockController that holds it in
  production;
- the holder of each immediate paymaster role (`SIGNER_ADMIN`, `PARAM_ADMIN`, `PAUSER`, `STAKE_ADMIN`,
  `TENANT_ADMIN`, `FEE_COLLECTOR`) in production.

Both canonical deployers SHALL be listed as out of ABIP-8 scope. The inventory SHALL say why: a deployer only places
contracts at addresses, and it holds no role or funds on any deployed contract once deployment ends. The deploy
tooling enforces this: it refuses a deployer as the paymaster `ROLE_ADMIN` (`contract-deployment`). If a deployer
ever holds a role, it SHALL be reclassified as in scope.

The inventory SHALL also state, for the canonical deployers:
- that each is used again for every upgrade target of its class, not once;
- what a leak allows. CREATE3 addresses do not depend on bytecode, so the holder of a leaked key can place any code
  at its class's canonical wallet implementation and factory addresses on a chain not yet adopted. Every user's
  wallet address on that chain is then controlled by that code, and assets sent there can be taken. A replacement
  deployer moves every later chain of the class to new addresses, so wallet addresses there no longer match the
  other chains.

Platform-admin API keys are bearer tokens, not private keys. They SHALL be listed as out of scope, with that reason.

#### Scenario: Unknown key found
- **WHEN** a service or tool reads a private key from an environment variable or secret that the inventory does not
  list
- **THEN** the key is treated as in ABIP-8 scope until it is classified, and the inventory is updated in the PR that
  introduces it

#### Scenario: Dev keys classified
- **WHEN** the inventory lists the anvil dev keys of `docs/E2E-DEV-KEYS.md` and the `dev` environment's Base Sepolia
  and Ethereum Sepolia keys
- **THEN** each is marked out of scope as a local or testnet-only key that can never hold real value

#### Scenario: Two deployers listed
- **WHEN** a reader looks up the canonical deployer in the inventory
- **THEN** they find two entries, mainnet and testnet, each marked out of ABIP-8 scope and kept in 1Password

#### Scenario: Deployer leak impact stated
- **WHEN** a reader looks up what a leaked canonical deployer key allows
- **THEN** the inventory says that it can take over every user's wallet address on chains of its class not yet
  adopted, and that replacing the key changes the wallet addresses of every chain adopted afterwards
