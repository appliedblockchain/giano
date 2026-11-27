## ADDED Requirements

### Requirement: Platform admins can read every chain's relay policy
`GET /v1/platform/chain-policies` SHALL list every served chain with its stored policy and version, each overridden field with its source, the effective policy with the source of each field, and the chain's problems. It SHALL require a platform admin session.

#### Scenario: An overridden field
- **WHEN** chain 8453's descriptor sets `allowedPaymasters`
- **THEN** the listing reports `allowedPaymasters` as overridden by `GIANO_CHAINS`, with the override's value as the effective one

#### Scenario: An undecided field in production
- **WHEN** a `production` deployment's chain has no decided `maxFeePerGas`
- **THEN** the chain's problems name `maxFeePerGas` and say that its operations are refused

### Requirement: Platform admins can edit a chain's stored relay policy
`PUT /v1/platform/chain-policies/:chainId` SHALL replace the stored policy of a served chain. It SHALL require `If-Match` with the current version, SHALL refuse an empty allowlist, a malformed address, a cap that is not a positive integer and an unknown field with 400 naming each one, and SHALL refuse a chain wallet-api does not serve with 404. `GET /v1/platform/chain-policies/:chainId/history` SHALL list the chain's changes, newest first.

#### Scenario: A valid edit
- **WHEN** a platform admin sends a valid policy with the current version
- **THEN** the policy is stored, the response carries the new version and effective policy, and the next operation on that chain uses it

#### Scenario: An empty allowlist
- **WHEN** a platform admin sends `allowedTargets: []`
- **THEN** the write is refused with 400, saying to send `"any"` or addresses

### Requirement: The console shows and edits each chain's relay policy
The paymaster console SHALL have a *Relay policy* tab for platform admins. For each served chain it SHALL show every field's effective value and source, and the chain's problems. A platform admin SHALL be able to edit the stored policy there. An overridden field SHALL be shown with its source and SHALL NOT be editable. Every save SHALL report its outcome on the page and in the browser console.

#### Scenario: A save refused by wallet-api
- **WHEN** a save is refused (validation, version conflict or session ended)
- **THEN** the dialog shows wallet-api's message next to the field it names, and nothing is reported as saved
