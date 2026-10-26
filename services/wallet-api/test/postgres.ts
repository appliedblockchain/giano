import type { StartedPostgreSqlContainer } from "@testcontainers/postgresql";
import pg from "pg";

/**
 * Stops a test Postgres once every other session has closed.
 *
 * pg-pool's `end()` resolves when it has asked its clients to end, not when they have, so a
 * container stopped straight after it can still hold their sessions. Postgres then sends those
 * sessions 57P01 ("terminating connection due to administrator command"), the pool re-emits it
 * with no listener, and vitest fails the run on an uncaught error after every test passed. Waiting
 * here makes that ordering deterministic, and turns a genuinely leaked connection into a clear
 * failure instead of an intermittent one.
 */
export async function stopPostgres(
	container: StartedPostgreSqlContainer | undefined,
	timeoutMs = 5_000,
): Promise<void> {
	if (!container) return;
	const client = new pg.Client({
		connectionString: container.getConnectionUri(),
	});
	await client.connect();
	try {
		const deadline = Date.now() + timeoutMs;
		for (;;) {
			const { rows } = await client.query<{ open: number }>(
				`SELECT count(*)::int AS open FROM pg_stat_activity WHERE backend_type = 'client backend' AND pid <> pg_backend_pid()`,
			);
			const open = rows[0]!.open;
			if (open === 0) break;
			if (Date.now() > deadline)
				throw new Error(
					`${open} Postgres connection(s) still open at teardown — a pool or client was not ended`,
				);
			await new Promise((resolve) => setTimeout(resolve, 20));
		}
	} finally {
		await client.end();
	}
	await container.stop();
}
