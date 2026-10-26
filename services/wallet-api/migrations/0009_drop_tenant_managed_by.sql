-- TENANTS_SEED is retired (openspec change retire-tenants-seed): Giano's platform admins are the only
-- writers of tenants, so a tenant no longer records who may write it. The release before this one
-- handed every seed-managed tenant to the platform admins at boot, with an `adopt` history entry each; a
-- deployment that skipped that release loses only those history entries, since every tenant is
-- managed by the platform admins once the column is gone.
--
-- tenant_admin_keys.created_by and tenant_history.actor keep their 'seed' values: they record who
-- wrote a key or a change, and that stays true.

ALTER TABLE tenants DROP COLUMN managed_by;
