-- Operators move from configuration (OPERATOR_ADDRESSES) into the database, so the operators
-- themselves can manage the list from the paymaster console (openspec change operators-in-database).
--
-- The init step (src/init.ts) writes an environment's bootstrap operators (src/environments.ts)
-- only into an EMPTY table. From then on only a signed-in operator changes it, every change is
-- recorded in operator_history, and the API refuses to remove the last operator or yourself.

CREATE TABLE operators (
  -- a label for logs and history, e.g. ops-oncall
  id text PRIMARY KEY CHECK (id ~ '^[a-z0-9-]{1,64}$'),
  -- the EOA that signs in as this operator; lowercase
  address text NOT NULL UNIQUE CHECK (address ~ '^0x[0-9a-f]{40}$'),
  -- 'bootstrap:<environment>' | 'operator:<id>:<address>'
  added_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Append-only. Rows outlive the operator they describe, so no foreign key to operators.
CREATE TABLE operator_history (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  operator_id text NOT NULL,
  address text NOT NULL,
  action text NOT NULL CHECK (action IN ('bootstrap', 'add', 'remove')),
  -- 'bootstrap:<environment>' | 'operator:<id>:<address>'
  actor text NOT NULL,
  operator_session_id uuid REFERENCES operator_sessions(id),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX operator_history_created_idx ON operator_history (created_at DESC);
