import { HStack, SimpleGrid, Stack, Text } from "@chakra-ui/react";
import {
	type ReactNode,
	useCallback,
	useEffect,
	useRef,
	useState,
} from "react";
import { getAdminConfig } from "../config";
import type { Usage, UsageFigures } from "../lib/platform-api";
import { usePlatform } from "../lib/platform-session";
import { useConsole } from "../shell/ConsoleContext";
import { SectionCard } from "./ui";
import { Amount } from "./values";

/** Usage over a week does not change by the minute: read it at most this often. */
export const USAGE_READ_EVERY_MS = 60_000;

/** Whether a refresh reads usage again: never read, another chain, or the last read is old enough. */
export function usageDue(
	last: { chainId: number; at: number } | undefined,
	chainId: number,
	now = Date.now(),
): boolean {
	return (
		!last || last.chainId !== chainId || now - last.at >= USAGE_READ_EVERY_MS
	);
}

/**
 * The selected chain's usage over the last seven days (B4), from wallet-api, read with the console's
 * refreshes but at most once a minute (USAGE_READ_EVERY_MS). Undefined where there is no platform
 * API, or wallet-api does not serve the endpoint (D11): the card is then absent, not a placeholder.
 */
export function useUsage(): Usage | undefined {
	const { platformApi } = getAdminConfig();
	const { run } = usePlatform();
	// Not `block`, which stays the same on an idle chain: the console's refreshes drive this.
	const { deployment, lastUpdated } = useConsole();
	const [usage, setUsage] = useState<Usage>();
	const notServed = useRef(false);
	const last = useRef<{ chainId: number; at: number }>(undefined);

	const read = useCallback(async () => {
		if (!platformApi || notServed.current) return;
		if (!usageDue(last.current, deployment.chainId)) return;
		last.current = { chainId: deployment.chainId, at: Date.now() };
		try {
			const result = await run((api) => api.usage(deployment.chainId));
			if (!result) return;
			if (result.ok) setUsage(result.value);
			else if (result.error.status === 404) {
				notServed.current = true;
				setUsage(undefined);
			}
			// another failure keeps the figures already shown: they are a week's, not a moment's
		} catch {
			// a network failure, or a proxy's non-JSON 5xx (run rethrows those): the same
		}
	}, [platformApi, run, deployment.chainId]);

	// biome-ignore lint/correctness/useExhaustiveDependencies: `lastUpdated` is a trigger: considered with every console refresh
	useEffect(() => {
		void read();
	}, [read, lastUpdated]);

	return usage?.chainId === deployment.chainId ? usage : undefined;
}

/** The refusal split as shown: whose to fix, with a count, the empty ones left out. */
export function refusalSplit(figures: UsageFigures): [string, number][] {
	const { refusedBy } = figures.decisions;
	return (
		[
			["the tenant's rules", refusedBy.rules],
			["the tenant's funds", refusedBy.funds],
			["the platform", refusedBy.platform],
			["other", refusedBy.other],
		] as [string, number][]
	).filter(([, count]) => count > 0);
}

/** Decisions and settlements, with refusals split by whose they are to fix. */
export function UsageCard({
	figures,
	title,
	subtitle,
	unknownTenant,
}: {
	figures: UsageFigures;
	title: string;
	subtitle: string;
	/** Another deployment's settlements on a shared paymaster: said, not counted. */
	unknownTenant?: UsageFigures;
}) {
	const { decisions } = figures;
	const split = refusalSplit(figures);
	return (
		<SectionCard title={title} subtitle={subtitle}>
			<Stack gap="3" data-testid="usage">
				<SimpleGrid columns={{ base: 2, md: 3, xl: 6 }} gap="3">
					<Figure label="Allowed" testId="usage-allowed">
						{decisions.allowed.toLocaleString()}
					</Figure>
					<Figure label="Refused" testId="usage-refused">
						{decisions.refused.toLocaleString()}
					</Figure>
					<Figure label="Settled">
						{figures.settled.toLocaleString()}
						{figures.reverted > 0 && (
							<Text as="span" fontSize="sm" color="fg.muted">
								{" "}
								({figures.reverted} reverted)
							</Text>
						)}
					</Figure>
					<Figure label="Gas">
						<Amount wei={BigInt(figures.gasWei)} decimals={6} />
					</Figure>
					<Figure label="Fees">
						<Amount wei={BigInt(figures.feeWei)} decimals={6} />
					</Figure>
					<Figure label="Overhead">
						<Amount wei={BigInt(figures.overheadWei)} decimals={6} />
					</Figure>
				</SimpleGrid>
				<Text fontSize="xs" color="fg.muted">
					Allowed and refused count decisions: every evaluation, including the
					estimate a wallet asks for before it sends an operation. Settled
					counts operations that landed.
				</Text>
				{unknownTenant && unknownTenant.settled > 0 && (
					<Text fontSize="xs" color="fg.muted" data-testid="usage-unknown">
						Not counted: {unknownTenant.settled.toLocaleString()} settlement
						{unknownTenant.settled === 1 ? "" : "s"} for tenants this deployment
						does not know, another deployment's on a shared paymaster.
					</Text>
				)}
				{split.length > 0 && (
					<HStack
						gap="2"
						flexWrap="wrap"
						fontSize="sm"
						data-testid="usage-refusals"
					>
						<Text color="fg.muted">Refused because of</Text>
						<Text>
							{split
								.map(([who, count]) => `${who}: ${count.toLocaleString()}`)
								.join(" · ")}
						</Text>
					</HStack>
				)}
			</Stack>
		</SectionCard>
	);
}

function Figure({
	label,
	children,
	testId,
}: {
	label: string;
	children: ReactNode;
	testId?: string;
}) {
	return (
		<Stack gap="0.5" borderWidth="1px" rounded="md" px="3" py="2">
			<Text
				fontSize="xs"
				textTransform="uppercase"
				letterSpacing="wide"
				color="fg.muted"
			>
				{label}
			</Text>
			<Text as="div" fontFamily="mono" fontSize="lg" data-testid={testId}>
				{children}
			</Text>
		</Stack>
	);
}
