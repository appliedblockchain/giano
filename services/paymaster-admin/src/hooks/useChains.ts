import { useCallback, useEffect, useRef, useState } from "react";
import { describeError } from "../lib/format";
import type { ChainsStatus } from "../lib/platform-api";
import { usePlatform } from "../lib/platform-session";
import { useConsole } from "../shell/ConsoleContext";

/**
 * wallet-api's view of every chain it serves (B3), read when the tab opens and with each console
 * refresh. Absent, not an error, where wallet-api does not serve the endpoint (D11); asked again
 * with each refresh, so a 404 during a rolling deploy does not hide it for the session.
 */
export function useChains(enabled: boolean) {
	const { run } = usePlatform();
	// Not `block`: it stays the same on an idle chain or a failed head read, and the chains are
	// read with every refresh (D25).
	const { lastUpdated } = useConsole();
	const [status, setStatus] = useState<ChainsStatus>();
	const [at, setAt] = useState<Date>();
	const [error, setError] = useState<string>();
	const [loading, setLoading] = useState(false);
	const [served, setServed] = useState(true);
	// A manual read and a refresh can overlap: only the latest one's answer counts.
	const generation = useRef(0);

	const read = useCallback(async () => {
		if (!enabled) return;
		const current = ++generation.current;
		setLoading(true);
		try {
			const result = await run((api) => api.chains());
			if (!result || current !== generation.current) return;
			if (result.ok) {
				setStatus(result.value);
				setAt(new Date());
				setError(undefined);
				setServed(true);
			} else if (result.error.status === 404) {
				setServed(false);
				setError(undefined);
			} else setError(result.error.message);
		} catch (cause) {
			if (current === generation.current) setError(describeError(cause));
		} finally {
			if (current === generation.current) setLoading(false);
		}
	}, [enabled, run]);

	// biome-ignore lint/correctness/useExhaustiveDependencies: `lastUpdated` is a trigger: read again with every console refresh
	useEffect(() => {
		void read();
	}, [read, lastUpdated]);

	return {
		status: served ? status : undefined,
		at,
		error: served ? error : undefined,
		// Enabled and served, and neither an answer nor a failure yet: not a pass.
		pending: enabled && served && status === undefined && !error,
		loading,
		read,
	};
}
