import { useCallback, useEffect, useState } from "react";
import { describeError } from "../lib/format";
import type { ChainsStatus } from "../lib/platform-api";
import { usePlatform } from "../lib/platform-session";
import { useConsole } from "../shell/ConsoleContext";

/**
 * wallet-api's view of every chain it serves (B3), read when the tab opens and with each console
 * refresh. Absent, not an error, where wallet-api does not serve the endpoint (D11).
 */
export function useChains(enabled: boolean) {
	const { run } = usePlatform();
	const { block } = useConsole();
	const [status, setStatus] = useState<ChainsStatus>();
	const [at, setAt] = useState<Date>();
	const [error, setError] = useState<string>();
	const [loading, setLoading] = useState(false);
	const [served, setServed] = useState(true);

	const read = useCallback(async () => {
		if (!enabled || !served) return;
		setLoading(true);
		try {
			const result = await run((api) => api.chains());
			if (!result) return;
			if (result.ok) {
				setStatus(result.value);
				setAt(new Date());
				setError(undefined);
			} else if (result.error.status === 404) setServed(false);
			else setError(result.error.message);
		} catch (cause) {
			setError(describeError(cause));
		} finally {
			setLoading(false);
		}
	}, [enabled, served, run]);

	// biome-ignore lint/correctness/useExhaustiveDependencies: `block` is a trigger: read again with every console refresh
	useEffect(() => {
		void read();
	}, [read, block]);

	return { status: served ? status : undefined, at, error, loading, read };
}
