import type { PendingRequest } from "../src/requests";

/** The pending consent request; fails the test when there is none. */
export function pendingOf(store: {
	readonly current: PendingRequest | null;
}): PendingRequest {
	const pending = store.current;
	if (!pending) throw new Error("expected a pending consent request");
	return pending;
}
