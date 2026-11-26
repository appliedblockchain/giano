## Purpose

Defines how wallet-api treats a tenant that its paymaster on a chain cannot sponsor, because the tenant is not registered there or is disabled there, so that the tenant is refused with a reason instead of authorised into an on-chain revert.

## ADDED Requirements

### Requirement: Sponsorship refuses a tenant its paymaster cannot sponsor
For a tenant whose sponsorship configuration on a chain is switched on and parses, every sponsorship decision on that chain SHALL read the tenant's record from the paymaster. When the tenant is not registered there, or is disabled there, wallet-api SHALL refuse with reason `sponsorship-disabled` before it reserves any balance or signs anything. A paymaster that cannot be read SHALL be refused as `temporarily-unavailable`, as today.

#### Scenario: Disabled on chain, with a balance
- **WHEN** a tenant with sponsorship switched on and a funded balance is disabled on the paymaster, and one of its users asks for paymaster data
- **THEN** the response is a refusal with reason `sponsorship-disabled`, no reservation is made and no authorisation is signed

#### Scenario: Not registered yet
- **WHEN** a tenant has switched sponsorship on and has not been registered on the paymaster
- **THEN** a request for paymaster stub data is refused with reason `sponsorship-disabled`, not `insufficient-balance`

#### Scenario: Re-enabled
- **WHEN** a tenant disabled on the paymaster is enabled again
- **THEN** the next decision for it is made by the sponsorship rules as before

### Requirement: The refusal names its rule
A refusal for the tenant's paymaster record SHALL be recorded in the decision log under the rule `paymaster-tenant`, failed, with a detail that says whether the tenant is not registered or disabled on the paymaster. A tenant whose configuration is off, missing or unparseable SHALL keep the rule and reason it has today.

#### Scenario: Detail for a disabled tenant
- **WHEN** a decision is refused because the tenant is disabled on the paymaster
- **THEN** its rule results include `paymaster-tenant`, failed, with the detail `disabled on the paymaster`

#### Scenario: Sponsorship switched off
- **WHEN** a tenant that is not registered on the paymaster has sponsorship switched off
- **THEN** the refusal is `sponsorship-disabled` under the rule `sponsorship-enabled`, as before
