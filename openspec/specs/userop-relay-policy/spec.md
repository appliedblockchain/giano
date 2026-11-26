# userop-relay-policy Specification

## Purpose
TBD - created by archiving change userop-policy-defaults. Update Purpose after archive.

## Requirements

### Requirement: The policy's purpose and rules are written down
The wallet-api README SHALL state what the relay policy protects (the shared bundler and its executor balance, each tenant, Giano as an operator) and, for each rule, one line naming the threat it addresses.

#### Scenario: A new rule
- **WHEN** a rule is added to `evaluatePolicy`
- **THEN** the README's rule list gains a line for it

### Requirement: Fee caps are meaningful on every served chain
The fee caps for a chain SHALL resolve from the chain descriptor's `walletApi.policy`, else the `USEROP_MAX_FEE_PER_GAS` / `USEROP_MAX_PRIORITY_FEE_PER_GAS` env vars when set, else wallet-api's default for that chain when it has one, else a fallback of 500 gwei. A tenant's overrides SHALL then apply. A `production` deployment SHALL refuse to boot when a served chain would use the fallback. A refusal by a fee cap SHALL be counted in `giano_userop_policy_rejections_total` with its rule and chain.

#### Scenario: Base with no configured caps
- **WHEN** a deployment serves Base (8453) and neither the descriptor nor the env sets a fee cap
- **THEN** an operation with `maxFeePerGas` above 10 gwei is refused under `max-fee-cap`

#### Scenario: Unknown chain in production
- **WHEN** a `production` deployment serves a chain wallet-api has no fee-cap default for, and neither its descriptor nor the env sets one
- **THEN** wallet-api refuses to boot and names the chain

### Requirement: Every gas field the bundler or paymaster pays for is bounded
The policy SHALL cap `callGasLimit`, `verificationGasLimit`, `preVerificationGas`, `paymasterVerificationGasLimit` and `paymasterPostOpGasLimit`. Each cap SHALL have a deployment default and SHALL be overridable in a chain descriptor and in a tenant policy. An operation with no paymaster SHALL pass the paymaster gas rules. `factory` and `factoryData` SHALL NOT be capped; the README SHALL record why.

#### Scenario: Oversized paymaster postOp limit
- **WHEN** an operation's `paymasterPostOpGasLimit` exceeds the resolved cap
- **THEN** it is refused under `paymaster-post-op-gas-cap` and the rejection is audit-logged

### Requirement: A tenant policy that cannot be parsed fails closed
When a tenant's stored policy does not parse, every relay for that tenant SHALL be refused under the rule `tenant-policy`. The refusal SHALL be audit-logged on `userop_log`, logged at error level, and counted in `giano_userop_policy_rejections_total{rule="tenant-policy"}`. The deployment defaults SHALL NOT be applied in its place.

#### Scenario: Corrupt stored policy
- **WHEN** a tenant's stored policy holds an unknown field or a malformed cap
- **THEN** its operations are refused with `tenant-policy` and nothing reaches the bundler

### Requirement: Allowlists are explicit choices
A target or paymaster allowlist SHALL accept `"any"` or a list of addresses, in a tenant's `perChain` entry, in a chain descriptor and in the single-chain env vars. Every tenant write path SHALL refuse an empty list in a tenant policy. An empty list already stored on a tenant, or in a chain descriptor, SHALL read as `"any"`.

#### Scenario: Empty list through the admin API
- **WHEN** a platform admin creates or patches a tenant with `perChain["8453"].allowedTargets: []`
- **THEN** the write is refused with a 400 that says to send `"any"` or addresses

#### Scenario: Recorded "any"
- **WHEN** a tenant's `perChain["8453"].allowedTargets` is `"any"`
- **THEN** any target is allowed on chain 8453

### Requirement: A tenant without its own allowlist inherits the deployment's choice
A tenant with no `perChain` entry for a chain SHALL inherit that chain's allowlists. A `production` deployment SHALL refuse to boot unless every served chain states both allowlists. wallet-api SHALL NOT refuse to boot because of a tenant row.

#### Scenario: Production without a stated allowlist
- **WHEN** a `production` deployment serves a chain whose descriptor has no `allowedTargets`
- **THEN** wallet-api refuses to boot and names the chain and the field
