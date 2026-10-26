import { readFileSync } from "node:fs";

/**
 * The release version `/v1/version` reports.
 *
 * Every Giano package and image shares one release version (INTEGRATION.md), but changesets
 * versions only the SDK packages, so the api reports theirs. A dApp's preflight compares it with
 * its connector, and a hardcoded fallback made every SDK look ahead of the api.
 *
 * The build inlines it (tsdown.config.ts); running from source (tests, `pnpm dev`) reads it from the
 * connector package instead.
 */
declare const __GIANO_RELEASE_VERSION__: string | undefined;

export const releaseVersion: string =
	typeof __GIANO_RELEASE_VERSION__ === "string"
		? __GIANO_RELEASE_VERSION__
		: (
				JSON.parse(
					readFileSync(
						new URL(
							"../../../packages/connector/package.json",
							import.meta.url,
						),
						"utf8",
					),
				) as { version: string }
			).version;
