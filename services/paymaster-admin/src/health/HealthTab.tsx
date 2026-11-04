import type {
	HealthCheck,
	HealthLevel,
	HealthReport,
} from "@appliedblockchain/giano-paymaster-sdk";
import { Button, Heading, HStack, Stack, Text } from "@chakra-ui/react";
import { useCallback, useEffect, useRef, useState } from "react";
import { LuArrowRight, LuRefreshCw } from "react-icons/lu";
import { StatusText } from "../components/status";
import { SectionCard } from "../components/ui";
import { getAdminConfig } from "../config";
import { driftChecks } from "../lib/drift";
import { amount, describeError } from "../lib/format";
import {
	CHAIN_THRESHOLDS,
	chainChecks,
	checkLink,
	groupChecks,
	HEALTH_GROUPS,
	signerCheck,
} from "../lib/health";
import type { ChainDrift, ChainsStatus } from "../lib/platform-api";
import { usePlatform } from "../lib/platform-session";
import { Link, tenantPath } from "../lib/router";
import { compareLedger, type TenantRow } from "../lib/tenants";
import { useConsole } from "../shell/ConsoleContext";

const LEVEL: Record<
	HealthLevel,
	{ tone: "green" | "orange" | "red"; label: string }
> = {
	ok: { tone: "green", label: "ok" },
	warn: { tone: "orange", label: "warning" },
	fail: { tone: "red", label: "failing" },
};

/**
 * The checks `giano-doctor` runs, evaluated in the browser from the overview on screen (openspec K7,
 * G7), grouped by what they are about. Same thresholds and verdicts as the CI gate: a console that
 * disagreed with it about whether a paymaster is usable would be worse than none.
 *
 * With the platform API, the Registry and chain group adds two checks only the console can make:
 * that every on-chain tenant has a registry row, and that wallet-api's ledger matches the chain.
 * They are approximate (openspec D10): the console compares at the block it read.
 */
export function HealthTab({
	health,
	rows,
}: {
	health: HealthReport;
	rows: readonly TenantRow[];
}) {
	const { platformApi } = getAdminConfig();
	const { deployment } = useConsole();
	const drift = useDrift(platformApi, deployment.chainId);
	// Where wallet-api reports drift for this chain, its comparison replaces the console's (D10):
	// it knows the block the watcher reached. Until it has answered, the console waits rather than
	// starting its own comparison, one request per tenant, for nothing.
	const ledger = useLedgerCheck(rows, platformApi && drift.state === "absent");
	const chains = useChains(platformApi);
	const money = (wei: bigint) =>
		`${amount(wei, deployment.nativeCurrency)} ${deployment.nativeCurrency.symbol}`;
	const extra: HealthCheck[] = !platformApi
		? []
		: drift.chain
			? driftChecks(drift.chain, money)
			: [registryRowsCheck(rows), ...(ledger.check ? [ledger.check] : [])];
	const chainRows = chains.status
		? chains.status.chains.map((chain) => ({
				chain,
				checks: chainChecks(chain),
			}))
		: [];
	const signer = chains.status ? signerCheck(chains.status.signer) : undefined;
	const groups = groupChecks([...health.checks, ...extra]);
	const all = [
		...health.checks,
		...extra,
		...(signer ? [signer] : []),
		...chainRows.flatMap((row) => row.checks),
	];
	const worst: HealthLevel = all.some((check) => check.level === "fail")
		? "fail"
		: all.some((check) => check.level === "warn")
			? "warn"
			: "ok";
	const counts = {
		fail: all.filter((check) => check.level === "fail").length,
		warn: all.filter((check) => check.level === "warn").length,
	};

	return (
		<Stack gap="4">
			<HStack
				gap="3"
				flexWrap="wrap"
				borderWidth="1px"
				rounded="lg"
				bg="surface"
				px="4"
				py="3"
				fontSize="sm"
				data-testid="health-summary"
			>
				<StatusText tone={LEVEL[worst].tone}>
					{worst === "ok"
						? "Every check passes"
						: [
								counts.fail && `${counts.fail} failing`,
								counts.warn &&
									`${counts.warn} warning${counts.warn === 1 ? "" : "s"}`,
							]
								.filter(Boolean)
								.join(", ")}
				</StatusText>
				<Text color="fg.muted">
					The checks the deployment gate runs, from the state the console last
					read.
				</Text>
			</HStack>
			{HEALTH_GROUPS.map(({ group, title, subtitle }) => (
				<SectionCard
					key={group}
					title={title}
					subtitle={subtitle}
					action={
						group === "registry" && platformApi ? (
							<Button
								size="sm"
								variant="ghost"
								aria-label="Compare the ledger again"
								loading={drift.chain ? drift.loading : ledger.loading}
								onClick={() => void (drift.chain ? drift.read() : ledger.run())}
							>
								<LuRefreshCw />
							</Button>
						) : undefined
					}
				>
					<Stack gap="0" data-testid={`health-${group}`}>
						{groups[group].map((check, index) => (
							<CheckRow key={check.id} check={check} first={index === 0} />
						))}
						{group === "registry" &&
							platformApi &&
							ledger.loading &&
							!ledger.check && (
								<Text fontSize="sm" color="fg.muted" pt="3">
									Comparing wallet-api's ledger with the chain…
								</Text>
							)}
					</Stack>
				</SectionCard>
			))}
			{(chains.status || chains.error) && (
				<SectionCard
					title="Chains"
					subtitle={`What wallet-api sees of each chain it serves, as of ${chains.at?.toLocaleTimeString() ?? "now"}. A head older than ${CHAIN_THRESHOLDS.headAgeWarnSeconds}s warns and ${CHAIN_THRESHOLDS.headAgeFailSeconds / 60} minutes fails; a ledger watcher more than ${CHAIN_THRESHOLDS.watcherLagWarnBlocks} blocks behind warns and ${CHAIN_THRESHOLDS.watcherLagFailBlocks.toLocaleString()} fails.`}
					action={
						<Button
							size="sm"
							variant="ghost"
							aria-label="Read the chains again"
							loading={chains.loading}
							onClick={() => void chains.read()}
						>
							<LuRefreshCw />
						</Button>
					}
				>
					<Stack gap="4" data-testid="health-chains">
						{chains.error && (
							<Text fontSize="sm" color="fg.error">
								Could not read the chains: {chains.error}
							</Text>
						)}
						{signer && (
							<Stack gap="0">
								<CheckRow check={signer} first noLink />
							</Stack>
						)}
						{chainRows.map(({ chain, checks }) => {
							const level = checks.some((check) => check.level === "fail")
								? "fail"
								: checks.some((check) => check.level === "warn")
									? "warn"
									: "ok";
							return (
								<Stack
									key={chain.chainId}
									gap="0"
									data-testid={`chain-${chain.chainId}`}
								>
									<HStack gap="3" pb="1">
										<Heading size="sm">
											{chain.name} · {chain.chainId}
										</Heading>
										<StatusText tone={LEVEL[level].tone}>
											{LEVEL[level].label}
										</StatusText>
									</HStack>
									{checks.map((check, index) => (
										<CheckRow
											key={check.id}
											check={check}
											first={index === 0}
											noLink
										/>
									))}
								</Stack>
							);
						})}
					</Stack>
				</SectionCard>
			)}
		</Stack>
	);
}

/**
 * wallet-api's drift for the selected chain (B5), read when the tab opens and with each console
 * refresh. `absent` where wallet-api does not serve the endpoint (D11), or does not sponsor this
 * chain, so keeps no ledger for it: the console then compares for itself.
 */
function useDrift(enabled: boolean, chainId: number) {
	const { run } = usePlatform();
	const { block } = useConsole();
	const [state, setState] = useState<"pending" | "served" | "absent">(
		enabled ? "pending" : "absent",
	);
	const [chain, setChain] = useState<ChainDrift>();
	const [loading, setLoading] = useState(false);
	/** A wallet-api without the endpoint will not grow one between refreshes. */
	const notServed = useRef(false);

	const read = useCallback(async () => {
		if (!enabled || notServed.current) return;
		setLoading(true);
		try {
			const result = await run((api) => api.drift());
			if (!result) return;
			if (result.ok) {
				const found = result.value.chains.find(
					(entry) => entry.chainId === chainId,
				);
				setChain(found);
				setState(found ? "served" : "absent");
			} else if (result.error.status === 404) {
				notServed.current = true;
				setState("absent");
			}
			// any other failure: keep the last answer, and fall back if there never was one
			else setState((current) => (current === "pending" ? "absent" : current));
		} catch {
			setState((current) => (current === "pending" ? "absent" : current));
		} finally {
			setLoading(false);
		}
	}, [enabled, run, chainId]);

	// biome-ignore lint/correctness/useExhaustiveDependencies: `block` is a trigger: read again with every console refresh
	useEffect(() => {
		void read();
	}, [read, block]);

	return {
		state,
		chain: state === "served" ? chain : undefined,
		loading,
		read,
	};
}

/**
 * wallet-api's view of every chain it serves (B3), read when the tab opens and with each console
 * refresh. Absent, not an error, where wallet-api does not serve the endpoint (D11).
 */
function useChains(enabled: boolean) {
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

function CheckRow({
	check,
	first,
	noLink,
}: {
	check: HealthCheck & { links?: { to: string; label: string }[] };
	first: boolean;
	/** For a check nothing in this console fixes. */
	noLink?: boolean;
}) {
	const level = LEVEL[check.level];
	const link = checkLink(check.id);
	return (
		<HStack
			justify="space-between"
			align="flex-start"
			gap="4"
			py="3"
			borderTopWidth={first ? "0" : "1px"}
			data-testid={`check-${check.id}`}
		>
			<Stack gap="1" minW="0">
				<HStack gap="3" flexWrap="wrap">
					<Text fontWeight="medium" fontSize="sm">
						{check.label}
					</Text>
					<StatusText tone={level.tone}>{level.label}</StatusText>
				</HStack>
				<Text fontSize="sm" color="fg.muted" wordBreak="break-word">
					{check.detail}
				</Text>
				{check.remedy && <Text fontSize="sm">What to do: {check.remedy}</Text>}
				{check.links && check.links.length > 0 && (
					<HStack gap="3" flexWrap="wrap" fontSize="sm">
						{check.links.map((entry) => (
							<Link key={entry.to} to={entry.to} color="brand.fg">
								{entry.label}
							</Link>
						))}
					</HStack>
				)}
			</Stack>
			{check.level !== "ok" && !noLink && (
				<Link
					to={link.to}
					fontSize="sm"
					color="brand.fg"
					fontWeight="medium"
					display="inline-flex"
					alignItems="center"
					gap="1"
					whiteSpace="nowrap"
				>
					{link.label} <LuArrowRight aria-hidden="true" />
				</Link>
			)}
		</HStack>
	);
}

/** Every tenant on this chain's paymaster is one wallet-api knows. */
function registryRowsCheck(
	rows: readonly TenantRow[],
): HealthCheck & { links?: { to: string; label: string }[] } {
	const orphans = rows.filter((row) => row.onChain && !row.registry);
	return orphans.length === 0
		? {
				id: "registry-rows",
				level: "ok",
				label: "Every on-chain tenant has a registry row",
				detail: `${rows.filter((row) => row.onChain).length} tenants on this chain, each known to wallet-api.`,
			}
		: {
				id: "registry-rows",
				level: "warn",
				label: "On-chain tenants with no registry row",
				detail: `${orphans.length} tenant${orphans.length === 1 ? " is" : "s are"} registered on this paymaster but unknown to wallet-api: another deployment's on a shared paymaster, or a registration whose tenant was never created.`,
				remedy:
					"Create the tenant in wallet-api with its id, or confirm it belongs to another deployment.",
				links: orphans
					.slice(0, 5)
					.map((row) => ({ to: tenantPath(row.id), label: row.id })),
			};
}

/**
 * wallet-api's ledger against the chain for every tenant with a registry row, read on demand: it is
 * one request per tenant, so it runs when the tab opens and when asked, not on every poll.
 */
function useLedgerCheck(rows: readonly TenantRow[], enabled: boolean) {
	const { run } = usePlatform();
	const { deployment, block } = useConsole();
	const [check, setCheck] = useState<
		(HealthCheck & { links?: { to: string; label: string }[] }) | undefined
	>();
	const [loading, setLoading] = useState(false);
	const candidates = rows.filter((row) => row.registry && row.onChain);
	const count = candidates.length;

	// biome-ignore lint/correctness/useExhaustiveDependencies: the candidates are read when asked; re-running on every poll is what this avoids
	const runCheck = useCallback(async () => {
		if (!enabled) return;
		setLoading(true);
		try {
			const differing: { slug: string; text: string }[] = [];
			const unread: string[] = [];
			const queue = [...candidates];
			const worker = async () => {
				for (let row = queue.shift(); row; row = queue.shift()) {
					const slug = row.registry?.slug;
					if (!slug || !row.onChain) continue;
					const result = await run((api) => api.detail(slug));
					if (!result?.ok) {
						unread.push(slug);
						continue;
					}
					const entry = result.value.ledger.find(
						(line) => line.chainId === deployment.chainId,
					);
					const comparison = compareLedger(entry, row.onChain, block);
					const empty =
						row.onChain.balance === 0n && row.onChain.deficit === 0n;
					if (comparison.kind === "differs") {
						const money = (wei: bigint) =>
							`${amount(wei, deployment.nativeCurrency)} ${deployment.nativeCurrency.symbol}`;
						differing.push({
							slug,
							text: `${slug}: ledger ${money(comparison.ledgerBalance)}, chain ${money(row.onChain.balance)}${comparison.lag !== undefined ? `, ${comparison.lag} blocks behind` : ", never synced"}`,
						});
					} else if (comparison.kind === "no-ledger" && !empty)
						differing.push({
							slug,
							text: `${slug}: no ledger row, chain holds a balance`,
						});
				}
			};
			await Promise.all(Array.from({ length: 5 }, worker));
			const compared = count - unread.length;
			setCheck(
				compared === 0
					? {
							id: "ledger",
							level: "warn",
							label: "Could not compare wallet-api's ledger with the chain",
							detail: `None of the ${count} tenants' records could be read from wallet-api, so nothing was compared.`,
							remedy:
								"Check wallet-api is reachable and your session is valid, then compare again.",
						}
					: differing.length === 0 && unread.length === 0
						? {
								id: "ledger",
								level: "ok",
								label: "wallet-api's ledger matches the chain",
								detail: `For all ${count} tenants with a registry row, at block ${block ?? "?"}.`,
							}
						: {
								id: "ledger",
								level: "warn",
								label:
									differing.length > 0
										? "wallet-api's ledger differs from the chain"
										: "wallet-api's ledger could not be compared for every tenant",
								detail: [
									...differing.map((entry) => entry.text),
									...(unread.length > 0
										? [
												`${unread.length} of ${count} tenants could not be read from wallet-api, so were not compared: ${unread.slice(0, 5).join(", ")}${unread.length > 5 ? "…" : ""}`,
											]
										: []),
								].join("; "),
								remedy:
									differing.length > 0
										? "A ledger a few blocks behind catches up on its own. One synced past the block read and still different is drift: check wallet-api's paymaster watcher."
										: "Compare again; if it keeps failing, check wallet-api.",
								links: [...differing.map((entry) => entry.slug), ...unread]
									.slice(0, 5)
									.map((slug) => ({ to: tenantPath(slug), label: slug })),
							},
			);
		} catch (cause) {
			setCheck({
				id: "ledger",
				level: "warn",
				label: "Could not compare wallet-api's ledger with the chain",
				detail: describeError(cause),
			});
		} finally {
			setLoading(false);
		}
	}, [enabled, run, deployment, block, count]);

	// biome-ignore lint/correctness/useExhaustiveDependencies: once when the tab opens with tenants to compare; again only when asked
	useEffect(() => {
		if (count > 0 && !check) void runCheck();
	}, [count]);

	return { check, loading, run: runCheck };
}
