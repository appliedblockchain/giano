-- dev cut-over to release v3: clear user data (decision D1, finding F8).
--
-- Run ONCE against dev's wallet-api database (`giano`), right after the roll to the v3 release
-- (TESTNET-ROLLOUT.md step 10, "Cut over dev"), when wallet-api's init container has applied the
-- migrations. One transaction: it either clears everything below or nothing.
--
-- Why: wallet-api stores each passkey's wallet address once, at registration
-- (credentials.wallet_address), and never recomputes it. After the switch those addresses are
-- legacy v0.7 accounts the v0.9 stack cannot operate, so every user starts again: they register a
-- passkey and get a v3 address.
--
-- Cleared: users and everything that depends on them (passkeys, sign-in challenges, sessions,
-- pending owner additions, the wallet-management, user-operation and sponsorship-decision logs),
-- the sponsorship ledger of the legacy paymaster (reservations, settlements) and the paymaster
-- watcher's cache, which is keyed by chain and still names the legacy paymaster. The watcher
-- rebuilds the cache from the v3 paymaster: its first reconcile reads every balance from the chain,
-- and its cursor starts again from a cold start.
--
-- Kept: tenants and all their configuration (admin keys, history, sponsorship rules, transaction
-- mappings, related origins), and the platform admins with their sessions.

BEGIN;

-- Counts before, for the record.
SELECT 'before' AS at,
  (SELECT count(*) FROM users) AS users,
  (SELECT count(*) FROM credentials) AS credentials,
  (SELECT count(*) FROM sessions) AS sessions,
  (SELECT count(*) FROM tenants) AS tenants,
  (SELECT count(*) FROM platform_admins) AS platform_admins;

-- Logs that reference users or sessions without ON DELETE CASCADE go first.
DELETE FROM sponsorship_decisions;
DELETE FROM wallet_management_log;
DELETE FROM userop_log;

-- Users cascade to credentials, challenges, sessions and pending_additions.
DELETE FROM users;

-- The legacy paymaster's sponsorship ledger and the watcher's cache.
DELETE FROM sponsorship_reservations;
DELETE FROM sponsorship_settlements;
DELETE FROM paymaster_tenants;
DELETE FROM paymaster_state;

-- Counts after: user data empty, tenants and admins unchanged.
SELECT 'after' AS at,
  (SELECT count(*) FROM users) AS users,
  (SELECT count(*) FROM credentials) AS credentials,
  (SELECT count(*) FROM sessions) AS sessions,
  (SELECT count(*) FROM tenants) AS tenants,
  (SELECT count(*) FROM platform_admins) AS platform_admins;

COMMIT;
