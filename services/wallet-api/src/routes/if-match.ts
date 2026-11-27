import type { FastifyRequest } from "fastify";

/** `"3"`, `W/"3"` or a bare `3`; null when present but not a version; undefined when absent. */
export function ifMatchVersion(
	request: FastifyRequest,
): number | null | undefined {
	const header = request.headers["if-match"];
	if (header === undefined) return undefined;
	const match = /^(?:W\/)?"?(\d+)"?$/.exec(String(header).trim());
	return match ? Number(match[1]) : null;
}
