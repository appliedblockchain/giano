import type { Knex } from 'knex';
import knex from 'knex';

const config: Knex.Config = {
  client: 'better-sqlite3',
  connection: {
    filename: './db.sqlite',
  },
  useNullAsDefault: true,
  pool: {
    min: 1,
    max: 15,
    propagateCreateError: false,
  },
  acquireConnectionTimeout: 1000,
  debug: true,
  log: {
    debug: ({ sql, bindings }) => {
      if (!sql || sql.includes('no-log')) return;
      console.log(`[QUERY] ${sql}`, bindings);
    },
  },
};

const database = knex(config);

await database.raw('SELECT 1 /* no-log */');

// ref: https://simplewebauthn.dev/docs/packages/server#additional-data-structures
// await database.raw(`DROP TABLE IF EXISTS authenticators`);
await database.raw(`
  CREATE TABLE IF NOT EXISTS authenticators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    credentialID TEXT UNIQUE NOT NULL,
    credentialPublicKey BLOB NOT NULL,
    counter INTEGER,
    credentialDeviceType TEXT,
    credentialBackedUp BOOL,
    transports JSONB
  );
`);

export default database;
