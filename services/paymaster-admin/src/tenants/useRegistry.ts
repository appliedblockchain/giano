import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { getAdminConfig } from "../config";
import { describeError } from "../lib/format";
import type { TenantSummary } from "../lib/platform-api";
import { usePlatform } from "../lib/platform-session";

export type Registry = {
	/** Live and deleted tenants together; undefined until the first read, and without the platform API. */
	tenants: TenantSummary[] | undefined;
	loading: boolean;
	error: string | undefined;
	/** Kept apart from `error`: the live tenants are still worth listing when only this half failed. */
	deletedError: string | undefined;
	reload: () => Promise<void>;
};

/**
 * wallet-api's tenant registry, live and deleted, re-read with every console refresh so the two
 * halves of the Tenants tab stay in step. Deleted tenants are always read: a tombstone still
 * explains a roster entry, even while the list hides it.
 */
export function useRegistry(lastUpdated: Date | undefined): Registry {
	const { platformApi } = getAdminConfig();
	const { run } = usePlatform();
	const [live, setLive] = useState<TenantSummary[]>();
	const [deleted, setDeleted] = useState<TenantSummary[]>([]);
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string>();
	const [deletedError, setDeletedError] = useState<string>();
	// Every console refresh reads again, so a slow read can land after a newer one: only the latest
	// read's answer is kept.
	const generation = useRef(0);

	const reload = useCallback(async () => {
		if (!platformApi) return;
		const current = ++generation.current;
		const latest = () => generation.current === current;
		setLoading(true);
		try {
			const [listed, tombstones] = await Promise.all([
				run((api) => api.list()),
				run((api) => api.list("deleted")),
			]);
			if (!latest()) return;
			if (!listed || !tombstones) return; // the session ended; the console is back on sign-in
			if (!listed.ok) return setError(listed.error.message);
			setError(undefined);
			setLive(listed.value.tenants);
			if (tombstones.ok) {
				setDeleted(tombstones.value.tenants);
				setDeletedError(undefined);
			} else {
				// Dropped rather than kept stale: the warning says the list has the live tenants only.
				setDeleted([]);
				setDeletedError(tombstones.error.message);
			}
		} catch (cause) {
			if (latest()) setError(describeError(cause));
		} finally {
			if (latest()) setLoading(false);
		}
	}, [platformApi, run]);

	// biome-ignore lint/correctness/useExhaustiveDependencies: `lastUpdated` is a trigger: every console refresh re-reads the registry too
	useEffect(() => {
		void reload();
	}, [reload, lastUpdated]);

	const tenants = useMemo(() => live && [...live, ...deleted], [live, deleted]);
	return {
		tenants,
		loading,
		error,
		deletedError,
		reload,
	};
}
