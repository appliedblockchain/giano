import type {
	HealthCheck,
	HealthLevel,
	HealthReport,
} from "@appliedblockchain/giano-paymaster-sdk";
import { Button, HStack, Stack, Text } from "@chakra-ui/react";
import { useCallback, useEffect, useState } from "react";
import { LuArrowRight, LuRefreshCw } from "react-icons/lu";
import { StatusText } from "../components/status";
import { SectionCard } from "../components/ui";
import { getAdminConfig } from "../config";
import { amount, describeError } from "../lib/format";
import { checkLink, groupChecks, HEALTH_GROUPS } from "../lib/health";
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
	const ledger = useLedgerCheck(rows, platformApi);
	const extra: HealthCheck[] = platformApi
		? [registryRowsCheck(rows), ...(ledger.check ? [ledger.check] : [])]
		: [];
	const groups = groupChecks([...health.checks, ...extra]);
	const all = [...health.checks, ...extra];
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
								loading={ledger.loading}
								onClick={() => void ledger.run()}
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
		</Stack>
	);
}

function CheckRow({
	check,
	first,
}: {
	check: HealthCheck & { links?: { to: string; label: string }[] };
	first: boolean;
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
			{check.level !== "ok" && (
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
			const queue = [...candidates];
			const worker = async () => {
				for (let row = queue.shift(); row; row = queue.shift()) {
					const slug = row.registry?.slug;
					if (!slug || !row.onChain) continue;
					const result = await run((api) => api.detail(slug));
					if (!result?.ok) continue;
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
			setCheck(
				differing.length === 0
					? {
							id: "ledger",
							level: "ok",
							label: "wallet-api's ledger matches the chain",
							detail: `For all ${count} tenants with a registry row, at block ${block ?? "?"}.`,
						}
					: {
							id: "ledger",
							level: "warn",
							label: "wallet-api's ledger differs from the chain",
							detail: differing.map((entry) => entry.text).join("; "),
							remedy:
								"A ledger a few blocks behind catches up on its own. One synced past the block read and still different is drift: check wallet-api's paymaster watcher.",
							links: differing.slice(0, 5).map((entry) => ({
								to: tenantPath(entry.slug),
								label: entry.slug,
							})),
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
