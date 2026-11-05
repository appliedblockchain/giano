-- Wallet session lifecycle (openspec change session-lifecycle, G5).
--
-- last_used_at drives the idle timeout: resolve() refuses a session idle for longer than
-- SESSION_IDLE_TIMEOUT_SECONDS, and touches the column at most once a minute. Existing rows take
-- their issue time, so a session issued before this release goes idle an hour after issue at the
-- latest: the safe direction for a control that ends sessions.
--
-- The partial index serves the hot paths that only care about sessions not yet revoked: the
-- per-user cap at issue, and revocation by user.
--
-- tenant_history gains 'user-sessions-revoke': a tenant admin key or a platform admin revoking a
-- user's sessions is recorded there, with the tenant left unchanged (before/after null).
--
-- Numbered 0011: 0010 is taken by usage_indexes (#210). The runner applies whatever is unapplied
-- in filename order, so either may land first.

ALTER TABLE sessions ADD COLUMN last_used_at timestamptz;
UPDATE sessions SET last_used_at = created_at;
ALTER TABLE sessions ALTER COLUMN last_used_at SET DEFAULT now();
ALTER TABLE sessions ALTER COLUMN last_used_at SET NOT NULL;

CREATE INDEX sessions_user_live_idx ON sessions (user_id, last_used_at) WHERE revoked_at IS NULL;

ALTER TABLE tenant_history DROP CONSTRAINT tenant_history_action_check;
ALTER TABLE tenant_history ADD CONSTRAINT tenant_history_action_check CHECK (action IN (
  'create', 'update', 'suspend', 'resume', 'delete',
  'admin-key-issue', 'admin-key-revoke', 'seed-apply', 'seed-takeover', 'adopt',
  'user-sessions-revoke'
));
