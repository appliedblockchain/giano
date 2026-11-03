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

/**
 * The selected chain's usage over the last seven days (B4), from wallet-api, read with each
 * console refresh. Undefined where there is no platform API, or wallet-api does not serve the
 * endpoint (D11): the card is then absent, not a placeholder.
 */
export function useUsage(): Usage | undefined {
	const { platformApi } = getAdminConfig();
	const { run } = usePlatform();
	const { deployment, block } = useConsole();
	const [usage, setUsage] = useState<Usage>();
	const notServed = useRef(false);

	const read = useCallback(async () => {
		if (!platformApi || notServed.current) return;
		const result = await run((api) => api.usage(deployment.chainId));
		if (!result) return;
		if (result.ok) setUsage(result.value);
		else if (result.error.status === 404) {
			notServed.current = true;
			setUsage(undefined);
		}
		// another failure keeps the figures already shown: they are a week's, not a moment's
	}, [platformApi, run, deployment.chainId]);

	// biome-ignore lint/correctness/useExhaustiveDependencies: `block` is a trigger: read again with every console refresh
	useEffect(() => {
		void read();
	}, [read, block]);

	return usage?.chainId === deployment.chainId ? usage : undefined;
}

/** Decisions and settlements, with refusals split by whose they are to fix. */
export function UsageCard({
	figures,
	title,
	subtitle,
}: {
	figures: UsageFigures;
	title: string;
	subtitle: string;
}) {
	const { decisions } = figures;
	const split = (
		[
			["the tenant's rules", decisions.refusedBy.rules],
			["the tenant's funds", decisions.refusedBy.funds],
			["the platform", decisions.refusedBy.platform],
			["other", decisions.refusedBy.other],
		] as const
	).filter(([, count]) => count > 0);
	return (
		<SectionCard title={title} subtitle={subtitle}>
			<Stack gap="3" data-testid="usage">
				<SimpleGrid columns={{ base: 2, md: 3, xl: 6 }} gap="3">
					<Figure label="Allowed">{decisions.allowed.toLocaleString()}</Figure>
					<Figure label="Refused">{decisions.refused.toLocaleString()}</Figure>
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

function Figure({ label, children }: { label: string; children: ReactNode }) {
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
			<Text as="div" fontFamily="mono" fontSize="lg">
				{children}
			</Text>
		</Stack>
	);
}
