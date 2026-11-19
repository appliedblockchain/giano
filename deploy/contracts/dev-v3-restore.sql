-- Rollback of dev-v3-reset.sql: put dev's user data back from the schema cutover_v3_backup.
--
-- "If it fails" in the Cut-over runbook (TESTNET-ROLLOUT.md). Run it with wallet-api scaled to 0,
-- with dev-db-run.sh, before rolling back to the legacy release. One transaction.
--
-- It first clears what release v3 wrote in the same tables since the reset: new users, and the v3
-- watcher's cache, whose cursor and balances belong to the v3 paymaster and would make the legacy
-- watcher skip events and report a false drawdown. Then it re-inserts every backed-up row. Columns are matched by name, so it also works after the v3
-- migrations have added columns: an added column takes its default. Platform admins and tenants
-- were never touched. The backup schema is kept; drop it once the cut-over is final:
--   DROP SCHEMA cutover_v3_backup CASCADE;

BEGIN;

DELETE FROM sponsorship_decisions;
DELETE FROM wallet_management_log;
DELETE FROM userop_log;
DELETE FROM challenges;
DELETE FROM users;
DELETE FROM sponsorship_reservations;
DELETE FROM sponsorship_settlements;
DELETE FROM paymaster_tenants;
DELETE FROM paymaster_state;

DO $$
DECLARE
  t text;
  cols text;
BEGIN
  -- Parents before children: sessions reference credentials, and sponsorship_decisions reference
  -- sponsorship_reservations, users and sessions.
  FOREACH t IN ARRAY ARRAY[
    'users', 'credentials', 'sessions', 'challenges', 'pending_additions',
    'sponsorship_reservations', 'sponsorship_settlements',
    'wallet_management_log', 'userop_log', 'sponsorship_decisions',
    'paymaster_tenants', 'paymaster_state'
  ] LOOP
    SELECT string_agg(quote_ident(b.column_name), ', ' ORDER BY b.ordinal_position) INTO cols
      FROM information_schema.columns b
      JOIN information_schema.columns c
        ON c.table_schema = 'public' AND c.table_name = t AND c.column_name = b.column_name
     WHERE b.table_schema = 'cutover_v3_backup' AND b.table_name = t;
    EXECUTE format('INSERT INTO public.%I (%s) SELECT %s FROM cutover_v3_backup.%I', t, cols, cols, t);
  END LOOP;
END
$$;

SELECT 'restored' AS at,
  (SELECT count(*) FROM users) AS users,
  (SELECT count(*) FROM credentials) AS credentials,
  (SELECT count(*) FROM sessions) AS sessions,
  (SELECT count(*) FROM tenants) AS tenants;

COMMIT;
