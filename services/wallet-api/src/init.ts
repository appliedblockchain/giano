/**
 * The init step: everything that must be true of the database before wallet-api serves, run as its
 * own container ahead of the API — an init container in the ECS task (infra/iac/ecs_services.tf),
 * an `init` service that wallet-api waits on in every compose file. wallet-api itself never seeds.
 *
 *   DATABASE_URL=… GIANO_ENVIRONMENT=dev node dist/init.js
 *
 * 1. Applies pending migrations.
 * 2. Writes the environment's bootstrap platform admins (src/environments.ts) — only into an empty
 *    platform admins table. Once a database has a platform admin, the table is the platform admins' to manage.
 * 3. On a local stack only, creates the test tenants in TENANT_FIXTURES that do not exist yet
 *    (services/tenant-fixtures.ts). Refused anywhere else, so no live configuration creates a tenant.
 *
 * Every step is safe to repeat and to run from several tasks at once. Exits non-zero on any
 * failure, which keeps the API from starting on a database that is not ready.
 */
import { createDb } from "./db/index.js";
import { resolveEnvironment } from "./environments.js";
import { runMigrations } from "./migrate.js";
import { bootstrapAdmins } from "./services/platform-admins.js";
import {
	loadTenantFixtures,
	parseTenantFixtures,
} from "./services/tenant-fixtures.js";

const fail = (message: string): never => {
	console.error(message);
	process.exit(1);
};

const databaseUrl =
	process.env.DATABASE_URL ?? fail("DATABASE_URL is required");
let environment!: ReturnType<typeof resolveEnvironment>;
try {
	environment = resolveEnvironment(process.env.GIANO_ENVIRONMENT);
} catch (error) {
	fail((error as Error).message);
}

const rawFixtures = process.env.TENANT_FIXTURES;
if (rawFixtures && !environment.localStack) {
	fail(
		`TENANT_FIXTURES is set, but "${environment.name}" is not a local stack — only platform admins create tenants there`,
	);
}
let fixtures: ReturnType<typeof parseTenantFixtures> = [];
try {
	if (rawFixtures) fixtures = parseTenantFixtures(rawFixtures);
} catch (error) {
	fail((error as Error).message);
}

const applied = await runMigrations(databaseUrl);
console.log(
	applied.length > 0
		? `Applied migrations: ${applied.join(", ")}`
		: "Migrations: up to date",
);

const { db, pool } = createDb(databaseUrl);
try {
	const seeded = await bootstrapAdmins(
		db,
		environment.name,
		environment.bootstrapAdmins,
	);
	console.log(
		seeded.length > 0
			? `Bootstrapped platform admins for ${environment.name}: ${seeded.join(", ")}`
			: `Platform admins: already present, or none to bootstrap for ${environment.name}`,
	);
	if (fixtures.length > 0) {
		const { created, existing } = await loadTenantFixtures(db, fixtures);
		if (created.length > 0)
			console.log(`Created fixture tenants: ${created.join(", ")}`);
		if (existing.length > 0)
			console.log(`Already present, left as they are: ${existing.join(", ")}`);
	}
} catch (error) {
	fail((error as Error).message);
} finally {
	await pool.end();
}
