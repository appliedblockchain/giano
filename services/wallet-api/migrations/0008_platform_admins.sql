-- Giano's own administrators — the platform admins — move from configuration (OPERATOR_ADDRESSES)
-- into the database, so they can manage the list themselves from the paymaster console (openspec
-- change platform-admins-in-database). The role was called "operator" until now; everything 0007
-- named after it is renamed here, and the actors already recorded are rewritten to the new prefix.
--
-- The init step (src/init.ts) writes an environment's bootstrap admins (src/environments.ts) only
-- into an EMPTY table. From then on only a signed-in platform admin changes it, every change is
-- recorded in platform_admin_history, and the API refuses to remove the last admin or yourself.

CREATE TABLE platform_admins (
  -- a label for logs and history, e.g. admin-oncall
  id text PRIMARY KEY CHECK (id ~ '^[a-z0-9-]{1,64}$'),
  -- the EOA that signs in as this admin; lowercase
  address text NOT NULL UNIQUE CHECK (address ~ '^0x[0-9a-f]{40}$'),
  -- 'bootstrap:<environment>' | 'platform-admin:<id>:<address>'
  added_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- 0007's sign-in state, renamed with the role.
ALTER TABLE operator_challenges RENAME TO platform_admin_challenges;
ALTER INDEX operator_challenges_expires_idx RENAME TO platform_admin_challenges_expires_idx;
ALTER TABLE operator_sessions RENAME TO platform_admin_sessions;
ALTER TABLE platform_admin_sessions RENAME COLUMN operator_id TO admin_id;
ALTER INDEX operator_sessions_expires_idx RENAME TO platform_admin_sessions_expires_idx;
ALTER TABLE tenant_history RENAME COLUMN operator_session_id TO platform_admin_session_id;

-- Append-only. Rows outlive the admin they describe, so no foreign key to platform_admins.
CREATE TABLE platform_admin_history (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  admin_id text NOT NULL,
  address text NOT NULL,
  action text NOT NULL CHECK (action IN ('bootstrap', 'add', 'remove')),
  -- 'bootstrap:<environment>' | 'platform-admin:<id>:<address>'
  actor text NOT NULL,
  platform_admin_session_id uuid REFERENCES platform_admin_sessions(id),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX platform_admin_history_created_idx ON platform_admin_history (created_at DESC);

-- 'operator:<id>:<address>' → 'platform-admin:<id>:<address>', so history reads in one vocabulary.
UPDATE tenant_history SET actor = 'platform-admin:' || substr(actor, length('operator:') + 1) WHERE actor LIKE 'operator:%';
UPDATE tenant_admin_keys SET created_by = 'platform-admin:' || substr(created_by, length('operator:') + 1) WHERE created_by LIKE 'operator:%';
