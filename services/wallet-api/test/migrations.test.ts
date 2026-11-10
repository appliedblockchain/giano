import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import {
	PostgreSqlContainer,
	type StartedPostgreSqlContainer,
} from "@testcontainers/postgresql";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createDb } from "../src/db/index.js";
import { runMigrations } from "../src/migrate.js";
import { pruneExpiredChallenges } from "../src/services/housekeeping.js";
import { stopPostgres } from "./postgres.js";

const MIGRATIONS_DIR = path.resolve(
	path.dirname(fileURLToPath(import.meta.url)),
	"..",
	"migrations",
);

/** A directory holding the migrations up to and including `prefix`, as a deployment at that release has them. */
function upTo(prefix: string): string {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "giano-migrations-"));
	for (const file of fs
		.readdirSync(MIGRATIONS_DIR)
		.filter((f) => f.endsWith(".sql") && f.slice(0, 4) <= prefix)) {
		fs.copyFileSync(path.join(MIGRATIONS_DIR, file), path.join(dir, file));
	}
	return dir;
}

/**
 * 0007 adds the tenant lifecycle to a table that already holds live tenants, so it must backfill
 * every existing row as an active, seed-managed tenant — anything else would suspend or orphan a
 * running deployment's tenants on upgrade.
 */
describe("migration 0007_tenant_lifecycle", () => {
	let container: StartedPostgreSqlContainer;
	let client: pg.Client;

	beforeAll(async () => {
		container = await new PostgreSqlContainer("postgres:17-alpine").start();
		// apply everything before 0007, as an upgraded deployment would have it
		const before = fs.mkdtempSync(path.join(os.tmpdir(), "giano-migrations-"));
		for (const file of fs
			.readdirSync(MIGRATIONS_DIR)
			.filter((f) => f.endsWith(".sql") && f < "0007")) {
			fs.copyFileSync(path.join(MIGRATIONS_DIR, file), path.join(before, file));
		}
		await runMigrations(container.getConnectionUri(), before);
		client = new pg.Client({ connectionString: container.getConnectionUri() });
		await client.connect();
		const { rows } = await client.query(
			`INSERT INTO tenants (slug, wallet_origin, rp_id, rp_name, expected_origins)
       VALUES ('acme', 'https://wallet.acme.app', 'wallet.acme.app', 'Acme', ARRAY['https://wallet.acme.app'])
       RETURNING id`,
		);
		await client.query(
			`INSERT INTO tenant_admin_keys (tenant_id, key_hash) VALUES ($1, 'abc')`,
			[rows[0].id],
		);
	});

	afterAll(async () => {
		await client?.end();
		await stopPostgres(container);
	});

	it("backfills existing tenants as active, seed-managed, version 1, and their keys as seed-created", async () => {
		expect(
			await runMigrations(container.getConnectionUri(), upTo("0007")),
		).toEqual(["0007_tenant_lifecycle.sql"]);
		const tenant = await client.query(
			`SELECT status, managed_by, version, status_changed_at FROM tenants WHERE slug = 'acme'`,
		);
		expect(tenant.rows[0]).toEqual({
			status: "active",
			managed_by: "seed",
			version: 1,
			status_changed_at: null,
		});
		const key = await client.query(`SELECT created_by FROM tenant_admin_keys`);
		expect(key.rows[0].created_by).toBe("seed");
	});

	it("refuses a status or owner outside the lifecycle", async () => {
		await expect(
			client.query(`UPDATE tenants SET status = 'archived'`),
		).rejects.toThrow(/check constraint/);
		await expect(
			client.query(`UPDATE tenants SET managed_by = 'tenant'`),
		).rejects.toThrow(/check constraint/);
	});

	it("creates the operator and history tables (renamed by 0008)", async () => {
		const { rows } = await client.query(
			`SELECT table_name FROM information_schema.tables
       WHERE table_name IN ('operator_challenges', 'operator_sessions', 'tenant_history') ORDER BY table_name`,
		);
		expect(rows.map((r) => r.table_name)).toEqual([
			"operator_challenges",
			"operator_sessions",
			"tenant_history",
		]);
	});

	it("is a no-op on a second run", async () => {
		expect(
			await runMigrations(container.getConnectionUri(), upTo("0007")),
		).toEqual([]);
	});

	it("0008 creates the platform admins, renames the operator tables and rewrites recorded actors", async () => {
		const {
			rows: [tenant],
		} = await client.query(`SELECT id FROM tenants WHERE slug = 'acme'`);
		await client.query(
			`INSERT INTO tenant_history (tenant_id, action, actor) VALUES ($1, 'suspend', 'operator:ops-a:0xabc')`,
			[tenant.id],
		);
		expect(
			await runMigrations(container.getConnectionUri(), upTo("0008")),
		).toEqual(["0008_platform_admins.sql"]);

		const tables = await client.query(
			`SELECT table_name FROM information_schema.tables WHERE table_name LIKE 'operator%' OR table_name LIKE 'platform_admin%' ORDER BY 1`,
		);
		expect(tables.rows.map((r) => r.table_name)).toEqual([
			"platform_admin_challenges",
			"platform_admin_history",
			"platform_admin_sessions",
			"platform_admins",
		]);
		expect(
			(
				await client.query(
					`SELECT actor FROM tenant_history WHERE action = 'suspend'`,
				)
			).rows,
		).toEqual([{ actor: "platform-admin:ops-a:0xabc" }]);

		await client.query(
			`INSERT INTO platform_admins (id, address, added_by) VALUES ('admin-a', '0x${"a".repeat(40)}', 'bootstrap:test')`,
		);
		await expect(
			client.query(
				`INSERT INTO platform_admins (id, address, added_by) VALUES ('admin-b', '0x${"A".repeat(40)}', 'x')`,
			),
		).rejects.toThrow(/check constraint/);
		await expect(
			client.query(
				`INSERT INTO platform_admins (id, address, added_by) VALUES ('Admin B', '0x${"b".repeat(40)}', 'x')`,
			),
		).rejects.toThrow(/check constraint/);
		await expect(
			client.query(
				`INSERT INTO platform_admin_history (admin_id, address, action, actor) VALUES ('admin-a', '0x', 'promote', 'x')`,
			),
		).rejects.toThrow(/check constraint/);
	});

	it("housekeeping drops challenges expired over a day ago and keeps younger ones", async () => {
		const { rows } = await client.query(
			`SELECT id FROM tenants WHERE slug = 'acme'`,
		);
		const tenantId = rows[0].id;
		for (const [challenge, age] of [
			["old", "2 days"],
			["recent", "1 hour"],
		]) {
			await client.query(
				`INSERT INTO challenges (challenge, kind, tenant_id, expires_at) VALUES ($1, 'registration', $2, now() - $3::interval)`,
				[challenge, tenantId, age],
			);
			await client.query(
				`INSERT INTO platform_admin_challenges (nonce, address, message, expires_at) VALUES ($1, '0xabc', 'm', now() - $2::interval)`,
				[challenge, age],
			);
		}
		const { db, pool } = createDb(container.getConnectionUri());
		try {
			await pruneExpiredChallenges(db);
		} finally {
			await pool.end();
		}
		expect(
			(await client.query(`SELECT challenge FROM challenges`)).rows.map(
				(r) => r.challenge,
			),
		).toEqual(["recent"]);
		expect(
			(
				await client.query(`SELECT nonce FROM platform_admin_challenges`)
			).rows.map((r) => r.nonce),
		).toEqual(["recent"]);
	});

	it("0009 drops managed_by and keeps every tenant, key and history as it was", async () => {
		await client.query(
			`UPDATE tenants SET managed_by = 'operator', version = 2 WHERE slug = 'acme'`,
		);
		expect(
			await runMigrations(container.getConnectionUri(), upTo("0009")),
		).toEqual(["0009_drop_tenant_managed_by.sql"]);
		const { rows } = await client.query(
			`SELECT column_name FROM information_schema.columns WHERE table_name = 'tenants' AND column_name = 'managed_by'`,
		);
		expect(rows).toEqual([]);
		expect(
			(await client.query(`SELECT slug, status, version FROM tenants`)).rows,
		).toEqual([{ slug: "acme", status: "active", version: 2 }]);
		expect(
			(await client.query(`SELECT created_by FROM tenant_admin_keys`)).rows,
		).toEqual([{ created_by: "seed" }]);
	});
	it("0010 adds the usage indexes, leading with the chain and the time", async () => {
		expect(
			await runMigrations(container.getConnectionUri(), upTo("0010")),
		).toEqual([
			"0010_usage_decisions_index.sql",
			"0010_usage_settlements_index.sql",
		]);
		const { rows } = await client.query(
			`SELECT indexname, indexdef FROM pg_indexes WHERE indexname IN ('sponsorship_decisions_chain_created_idx', 'sponsorship_settlements_chain_observed_idx') ORDER BY 1`,
		);
		expect(rows.map((row) => row.indexname)).toEqual([
			"sponsorship_decisions_chain_created_idx",
			"sponsorship_settlements_chain_observed_idx",
		]);
		expect(rows[0].indexdef).toContain("(chain_id, created_at)");
		expect(rows[1].indexdef).toContain("(chain_id, observed_at)");
	});

	it("0011 dates every existing session's last use to its issue, and accepts the session revocation history action", async () => {
		const {
			rows: [tenant],
		} = await client.query(`SELECT id FROM tenants WHERE slug = 'acme'`);
		const {
			rows: [user],
		} = await client.query(
			`INSERT INTO users (tenant_id, external_id) VALUES ($1, 'user-1') RETURNING id`,
			[tenant.id],
		);
		const {
			rows: [credential],
		} = await client.query(
			`INSERT INTO credentials (tenant_id, user_id, credential_id, rp_id, cose_public_key, public_key_x, public_key_y, wallet_address)
       VALUES ($1, $2, 'cred-1', 'wallet.acme.app', '\\x00', '0x01', '0x02', '0x${"c".repeat(40)}') RETURNING id`,
			[tenant.id, user.id],
		);
		await client.query(
			`INSERT INTO sessions (user_id, credential_id, wallet_address, token_hash, created_at, expires_at)
       VALUES ($1, $2, '0x${"c".repeat(40)}', 'hash-1', now() - interval '3 hours', now() + interval '21 hours')`,
			[user.id, credential.id],
		);

		expect(await runMigrations(container.getConnectionUri())).toEqual([
			"0011_session_lifecycle.sql",
		]);

		expect(
			(
				await client.query(
					`SELECT last_used_at = created_at AS backfilled FROM sessions WHERE token_hash = 'hash-1'`,
				)
			).rows,
		).toEqual([{ backfilled: true }]);
		const {
			rows: [fresh],
		} = await client.query(
			`INSERT INTO sessions (user_id, credential_id, wallet_address, token_hash, expires_at)
       VALUES ($1, $2, '0x${"c".repeat(40)}', 'hash-2', now() + interval '1 day') RETURNING last_used_at IS NOT NULL AS stamped`,
			[user.id, credential.id],
		);
		expect(fresh).toEqual({ stamped: true });
		expect(
			(
				await client.query(
					`SELECT indexdef FROM pg_indexes WHERE indexname = 'sessions_user_live_idx'`,
				)
			).rows[0].indexdef,
		).toMatch(/\(user_id, last_used_at\) WHERE \(revoked_at IS NULL\)/);
		expect(
			(
				await client.query(
					`SELECT indexdef FROM pg_indexes WHERE indexname = 'sessions_wallet_live_idx'`,
				)
			).rows[0].indexdef,
		).toMatch(/\(lower\(wallet_address\)\) WHERE \(revoked_at IS NULL\)/);

		await client.query(
			`INSERT INTO tenant_history (tenant_id, action, actor, detail)
       VALUES ($1, 'user-sessions-revoke', 'tenant-admin-key:k1', '{"selector":"externalUserId","value":"user-1","revoked":1}')`,
			[tenant.id],
		);
		await expect(
			client.query(
				`INSERT INTO tenant_history (tenant_id, action, actor) VALUES ($1, 'session-purge', 'x')`,
				[tenant.id],
			),
		).rejects.toThrow(/check constraint/);
	});
});
