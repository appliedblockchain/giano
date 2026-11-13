# Tasks

## 1. Rules

- [x] 1.1 Replace the structural wallet-management test with `OWNER_MANAGEMENT_SELECTORS` (`addOwnerAddress`, `addOwnerPublicKey`, `removeOwnerAtIndex`) and a plain value transfer to self (design D1, D2, D4).
- [x] 1.2 Carry each call's `value` in `decodeInnerCalls`, and refuse an owner function called with value (design D3).
- [x] 1.3 Classify each call once (`classifyCall`), and record a refused self-call under the rule `self-calls` with reason `contract-not-allowed` (design D5, D6).
- [x] 1.4 Unit tests in `services/wallet-api/test/sponsorship-rules.test.ts`: each owner function sponsored, the set has three entries, plain transfer to self sponsored, and every refused self-call in the spec refused under `self-calls`.

## 2. E2E

- [x] 2.1 `e2e/tests/sponsorship.spec.ts`: adding a passkey from the stock wallet's management view is paid by the sponsorship paymaster and settled on the tenant's books.

## 3. Docs

- [x] 3.1 `specs/INTEGRATION.md` §7.1 and the refusal table describe the list and the `contract-not-allowed` refusal of other self-calls.
- [x] 3.2 `specs/PAYMASTER-SPECS.md` rules table and explanation.
- [x] 3.3 Comments that relied on the structural rule: `packages/wallet-kit/src/management/preflight.ts`, `e2e/tests/sponsorship.spec.ts`.

## 4. Follow-ups (not in this change)

- [ ] 4.1 Decide whether a plain value transfer to self stays wallet management (design, Open Questions).
- [ ] 4.2 G40: on-chain checks for the wallet implementation and `initCode`.
