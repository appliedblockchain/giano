## MODIFIED Requirements

### Requirement: Every tenant write is recorded and attributed
Every tenant write SHALL append a history entry in the same transaction as the write. That covers create, update, suspend, resume, delete, admin-key issue and revoke, seed apply, seed takeover and adopt. A revocation of a user's sessions by a tenant admin key or a platform admin SHALL also append an entry, with action `user-sessions-revoke`, even when it revoked nothing. Each entry records:
- the action;
- the actor: `seed`, `platform-admin:<id>:<address>`, or `tenant-admin-key:<keyId>` for a revocation made with a tenant admin key;
- the platform admin session, for platform admin writes;
- the tenant before and after the write, except for `user-sessions-revoke`, which leaves both empty because the tenant does not change;
- for key actions, the key id, label and hash prefix;
- for `user-sessions-revoke`, the selector used (`externalUserId` or `walletAddress`) and its value, and the number of sessions revoked.

Entries SHALL never contain key material or session tokens. A boot that changes nothing SHALL write no entry. `GET /v1/platform/tenants/:slug/history?before=` SHALL return entries newest first, 50 per page, with a cursor for the next page.

#### Scenario: Attribution
- **WHEN** platform admin `ops-a` suspends a tenant
- **THEN** the newest history entry has action `suspend`, actor `platform admin:ops-a:<address>` and that platform admin's session

#### Scenario: Idle restart
- **WHEN** `wallet-api` restarts with an unchanged `TENANTS_SEED`
- **THEN** no history entry is written

#### Scenario: Session revocation by a tenant admin key
- **WHEN** a tenant admin key with id `k1` revokes the sessions of `externalUserId` `user-7`, and two sessions are revoked
- **THEN** the newest history entry has action `user-sessions-revoke`, actor `tenant-admin-key:k1`, no platform admin session, empty before and after, and detail `{ selector: "externalUserId", value: "user-7", revoked: 2 }`

#### Scenario: Session revocation by a platform admin
- **WHEN** platform admin `ops-a` revokes by `walletAddress` on a tenant
- **THEN** the newest history entry has action `user-sessions-revoke`, actor `platform-admin:ops-a:<address>` and that platform admin's session
