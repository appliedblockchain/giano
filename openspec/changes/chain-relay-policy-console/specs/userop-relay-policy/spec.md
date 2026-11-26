## ADDED Requirements

### Requirement: Each chain's relay policy is stored in the database
wallet-api SHALL keep one relay policy per served chain in the database, with a version, the last writer and the time of the last write. Every write SHALL be recorded in an append-only history with its actor and the policy before and after.

#### Scenario: A platform admin changes a chain's paymaster allowlist
- **WHEN** a platform admin replaces chain 8453's stored policy with the current version in `If-Match`
- **THEN** the row's version increases, and the history records the actor, the old policy and the new one

#### Scenario: Two platform admins edit the same chain
- **WHEN** a write carries a version older than the stored one
- **THEN** it is refused with 412 and the stored policy is unchanged

### Requirement: A chain with no stored policy is seeded with safe defaults
When wallet-api starts, it SHALL write a policy for every served chain that has none, and SHALL NOT change an existing one. The seed SHALL set the gas caps to the deployment defaults, the fee caps to wallet-api's known values for the chain when it has them, `allowedTargets` to `"any"`, and `allowedPaymasters` to the chain's own Giano sponsorship paymaster when it has one. If the seed cannot be written, wallet-api SHALL NOT start.

#### Scenario: First boot on Base
- **WHEN** wallet-api starts serving Base (8453) with no stored policy for it
- **THEN** it stores a policy with the Base fee caps, `allowedTargets: "any"` and `allowedPaymasters` set to Base's Giano paymaster, and records a `seed` history entry

#### Scenario: Restart
- **WHEN** wallet-api restarts and chain 8453 already has a stored policy
- **THEN** the stored policy is unchanged

### Requirement: Env vars override the stored policy field by field
For each field, the chain descriptor's `walletApi.policy` SHALL win, then the matching `USEROP_*` env var when set, then the stored value. The `USEROP_*` cap env vars SHALL have no built-in default.

#### Scenario: GIANO_CHAINS overrides the paymaster allowlist
- **WHEN** chain 8453's descriptor sets `allowedPaymasters` and the stored policy sets a different list
- **THEN** the relay applies the descriptor's list, and the platform API reports the field as overridden by `GIANO_CHAINS`

## MODIFIED Requirements

### Requirement: Fee caps are meaningful on every served chain
The fee caps for a chain SHALL resolve from the chain descriptor's `walletApi.policy`, else the `USEROP_MAX_FEE_PER_GAS` / `USEROP_MAX_PRIORITY_FEE_PER_GAS` env vars when set, else the chain's stored relay policy. A tenant's overrides SHALL then apply. When none of them sets a fee cap, a non-production deployment SHALL use a fallback of 500 gwei, and a `production` deployment SHALL refuse every operation on that chain under `chain-policy`. A refusal by a fee cap SHALL be counted in `giano_userop_policy_rejections_total` with its rule and chain.

#### Scenario: Base with the seeded policy
- **WHEN** a deployment serves Base (8453) with its seeded policy and no override
- **THEN** an operation with `maxFeePerGas` above 10 gwei is refused under `max-fee-cap`

#### Scenario: Unknown chain in production
- **WHEN** a `production` deployment serves a chain whose stored policy has no fee cap, and nothing overrides it
- **THEN** wallet-api starts, logs the problem at error level, and refuses every operation on that chain under `chain-policy`, naming the chain and the field

### Requirement: A tenant without its own allowlist inherits the deployment's choice
A tenant with no `perChain` entry for a chain SHALL inherit that chain's allowlists, resolved from overrides and the stored policy. When neither decides an allowlist, a non-production deployment SHALL allow any address, and a `production` deployment SHALL refuse every operation on that chain under `chain-policy`. wallet-api SHALL NOT refuse to boot because of a chain policy or a tenant row.

#### Scenario: Production without a decided allowlist
- **WHEN** a `production` deployment serves a chain whose stored policy has no `allowedPaymasters`, and nothing overrides it
- **THEN** operations on that chain are refused under `chain-policy`, and the other chains are unaffected

### Requirement: A stored chain policy that cannot be parsed fails closed
When a chain's stored policy does not parse, every operation on that chain SHALL be refused under `chain-policy` in every deployment class. The refusal SHALL be audit-logged on `userop_log`, logged at error level, and counted in `giano_userop_policy_rejections_total{rule="chain-policy"}`.

#### Scenario: A hand-edited row
- **WHEN** chain 8453's stored policy holds an unknown field
- **THEN** its operations are refused under `chain-policy` and nothing reaches the bundler
