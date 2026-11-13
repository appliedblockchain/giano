## Why

The sponsorship rules (`evaluateSponsorship` in wallet-api) decide when wallet-api signs a paymaster authorisation, which makes the tenant pay the gas. The on-chain paymaster only checks that signature and never reads the calldata, so these rules are the only check on what the tenant pays for.

Until this change, every call from the wallet to itself counted as wallet management. Wallet management is sponsored by default under the platform cap and skips the tenant's allowlist. The wallet's `onlyOwner` accepts a call from the wallet to itself, and several wallet functions run calls or code they carry as a payload (`execute`, `executeBatch`, `executeWithoutChainIdValidation`, `upgradeToAndCall`, `signedStaticCall`). So any signed-in user of a tenant with sponsorship enabled could hide any call inside a self-call, and the tenant paid for it. Applied Edge finding: `wallet-api-sponsorship-nested-self-call-allowlist-bypass` (High).

## What Changes

- **BREAKING (sponsorship policy):** wallet management is detected by a list of allowed wallet functions, not "by shape". Only `addOwnerAddress`, `addOwnerPublicKey` and `removeOwnerAtIndex`, called with no value, and a plain value transfer to self (calldata `0x`) are sponsored as wallet management.
- Every other self-call is refused with `contract-not-allowed`, and the decision table records it under a new rule, `self-calls`. This includes `execute`, `executeBatch`, `executeWithoutChainIdValidation`, `upgradeToAndCall`, `signedStaticCall`, `removeLastOwner`, unknown selectors and calldata of 1 to 3 bytes.
- Wallet upgrades are no longer sponsored. No code sends upgrades today.
- `removeLastOwner` is not sponsored. It locks the wallet for good, and the product never builds it (WM-28).
- An owner function called with value is refused. The owner functions are not payable, so the call always reverts.
- The rules classify each call once (`application`, `wallet-management` or `refused-self-call`), and every rule reads that result.
- `specs/INTEGRATION.md` and `specs/PAYMASTER-SPECS.md` describe the list instead of the structural rule.

**Non-goals.**
- Checking that the sender runs the canonical wallet implementation, and binding `initCode` to the sponsorship authorisation. Both need a paymaster contract change. Ticket G40 tracks them.
- A separate refusal reason for a refused self-call. The reason stays `contract-not-allowed`, which every wallet already handles.
- Whether a plain value transfer to self should stay wallet management, or need its own tenant opt-in. This is a policy decision, recorded as an open question in `design.md`.
- Per-user limits on sponsored operations.

## Capabilities

### New Capabilities
- `sponsorship-self-calls`: which calls from a wallet to itself wallet-api sponsors as wallet management, and how it refuses and records the others.

### Modified Capabilities

None. No current OpenSpec spec covers the sponsorship rules.

## Impact

- **Code:** `services/wallet-api/src/services/sponsorship-rules.ts` and its tests.
- **Comments:** `packages/wallet-kit/src/management/preflight.ts` (no behaviour change, so no changeset).
- **E2E:** `e2e/tests/sponsorship.spec.ts` gains a test that adding a passkey is sponsored and settled on the tenant's books.
- **Docs:** `specs/INTEGRATION.md`, `specs/PAYMASTER-SPECS.md`.
- **Integrators:** a wallet that sends a self-call other than the three owner functions or a plain transfer to self now gets `contract-not-allowed`. The stock wallet and wallet-kit send only those.
