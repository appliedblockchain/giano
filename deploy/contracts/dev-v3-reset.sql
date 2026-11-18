-- dev cut-over to release v3: clear user data (decision D1, finding F8).
--
-- Step 7 of the "Cut-over runbook" in TESTNET-ROLLOUT.md. Run it ONCE, with wallet-api scaled to 0
-- (runbook step 6), on the schema dev runs before the roll: every table below exists from release
-- 5ba71241 on. Run it with dev-db-run.sh, which executes it in a one-off wallet-api task.
--
-- Why: wallet-api stores each passkey's wallet address once, at registration
-- (credentials.wallet_address), and never recomputes it. After the switch those addresses are
-- legacy v0.7 accounts the v0.9 stack cannot operate, so every user starts again: they register a
-- passkey and get a v3 address.
--
-- Cleared: users and everything about them (passkeys, sign-in and registration challenges,
-- sessions, pending owner additions, the wallet-management, user-operation and
-- sponsorship-decision logs), the legacy paymaster's sponsorship ledger (reservations,
-- settlements), and the paymaster watcher's cache (paymaster_state, paymaster_tenants). That cache
-- is keyed by chain and still names the legacy paymaster; empty, the v3 watcher cold-starts and its
-- first reconcile reads every balance from the v3 paymaster (finding F18).
--
-- Kept: tenants and all their configuration (admin keys, history, sponsorship rules, transaction
-- mappings, related origins), and the platform admins with their sessions.
--
-- Every cleared row is first copied into the schema cutover_v3_backup, in the same transaction.
-- dev-v3-restore.sql puts them back. A second run fails on CREATE SCHEMA and changes nothing.

BEGIN;

SELECT 'before' AS at,
  (SELECT count(*) FROM users) AS users,
  (SELECT count(*) FROM credentials) AS credentials,
  (SELECT count(*) FROM sessions) AS sessions,
  (SELECT count(*) FROM challenges) AS challenges,
  (SELECT count(*) FROM tenants) AS tenants,
  (SELECT count(*) FROM platform_admins) AS platform_admins;

CREATE SCHEMA cutover_v3_backup;
CREATE TABLE cutover_v3_backup.users AS TABLE users;
CREATE TABLE cutover_v3_backup.credentials AS TABLE credentials;
CREATE TABLE cutover_v3_backup.challenges AS TABLE challenges;
CREATE TABLE cutover_v3_backup.sessions AS TABLE sessions;
CREATE TABLE cutover_v3_backup.pending_additions AS TABLE pending_additions;
CREATE TABLE cutover_v3_backup.wallet_management_log AS TABLE wallet_management_log;
CREATE TABLE cutover_v3_backup.userop_log AS TABLE userop_log;
CREATE TABLE cutover_v3_backup.sponsorship_decisions AS TABLE sponsorship_decisions;
CREATE TABLE cutover_v3_backup.sponsorship_reservations AS TABLE sponsorship_reservations;
CREATE TABLE cutover_v3_backup.sponsorship_settlements AS TABLE sponsorship_settlements;
CREATE TABLE cutover_v3_backup.paymaster_tenants AS TABLE paymaster_tenants;
CREATE TABLE cutover_v3_backup.paymaster_state AS TABLE paymaster_state;

-- The logs reference users and sessions ON DELETE SET NULL, so the order does not matter; they are
-- cleared because they record legacy wallets.
DELETE FROM sponsorship_decisions;
DELETE FROM wallet_management_log;
DELETE FROM userop_log;
-- Registration challenges can have no user (user_id NULL), so they are cleared on their own.
DELETE FROM challenges;
-- Users cascade to credentials, sessions and pending_additions.
DELETE FROM users;
DELETE FROM sponsorship_reservations;
DELETE FROM sponsorship_settlements;
DELETE FROM paymaster_tenants;
DELETE FROM paymaster_state;

SELECT 'after' AS at,
  (SELECT count(*) FROM users) AS users,
  (SELECT count(*) FROM credentials) AS credentials,
  (SELECT count(*) FROM sessions) AS sessions,
  (SELECT count(*) FROM challenges) AS challenges,
  (SELECT count(*) FROM tenants) AS tenants,
  (SELECT count(*) FROM platform_admins) AS platform_admins;

COMMIT;
