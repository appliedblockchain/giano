# Tasks

## 1. Sponsorship

- [x] 1.1 `sponsorship-service.ts`: read the tenant's paymaster record with the fee (`PaymasterReader.tenant`), and refuse a tenant whose configuration is on and which is not registered or is disabled, with reason `sponsorship-disabled` and rule `paymaster-tenant`, before the rules, the reservation and the signature (design D1–D3).
- [x] 1.2 The fake paymaster reader in `test/setup.ts` reports `enabled` from its `disabled` set, as its roster does.
- [x] 1.3 `test/sponsorship-api.test.ts`: disabled with a balance (no reservation, no signature), not registered, switched off keeps its rule, re-enabled.

## 2. Drift

- [x] 2.1 `services/drift.ts`: `unregistered` per chain, from active tenants with sponsorship switched on for the chain and not on the roster (design D4).
- [x] 2.2 `routes/platform-drift.ts` returns it; `plugins/metrics.ts` and `index.ts` set and remove `giano_paymaster_unregistered_tenants`.
- [x] 2.3 `packages/contracts/scripts/doctor-drift.ts` warns on it; tests in `deploy/doctor-drift.test.ts`.
- [x] 2.4 `test/platform-drift.test.ts`: listed when configured and unregistered, not listed without configuration or when suspended.

## 3. Docs

- [x] 3.1 `docs/TENANT-OFFBOARDING-RUNBOOK.md`.
- [x] 3.2 `specs/PLATFORM-ADMIN-SPECS.md` links the runbook from §5 and records the sponsorship check and the unregistered list.
- [x] 3.3 Empty changeset: the doctor is not part of the published contracts package.

## 4. Follow-ups (not in this change)

- [ ] 4.1 Alert on `giano_paymaster_drifted_tenants` and `giano_paymaster_unregistered_tenants`. Datadog first needs to scrape wallet-api's `/metrics` (infra).
- [ ] 4.2 Decide retention or erasure for a deleted tenant's users, credentials and logs (design, Open Questions; G34).
- [ ] 4.3 Decide whether the on-chain disable should be enforced on suspend or delete rather than offered by the console.
- [ ] 4.4 Decide the users' notice period before suspend, and who tells them: once the wallet origin is gone, a passkey bound to its RP ID can no longer sign (runbook §4).
- [ ] 4.5 O-3 in `specs/PLATFORM-ADMIN-SPECS.md`: the network restriction on `/v1/platform/*` is still open.
