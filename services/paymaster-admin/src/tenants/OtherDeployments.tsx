import {
	GianoPaymasterClient,
	type TenantView,
} from "@appliedblockchain/giano-paymaster-sdk";
import { Button, HStack, Spinner, Stack, Table, Text } from "@chakra-ui/react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { SectionCard } from "../components/ui";
import { type Deployment, deploymentKey, getAdminConfig } from "../config";
import { createReadClient } from "../lib/chain";
import { amount, describeError } from "../lib/format";
import type { TenantDetail } from "../lib/platform-api";
import { usePlatform } from "../lib/platform-session";
import { OnChainBadge } from "../platform/shared";
import { useConsole } from "../shell/ConsoleContext";

export type Reading =
	| { kind: "loading" }
	| { kind: "registered"; tenant: TenantView }
	| { kind: "not-registered" }
	| { kind: "no-paymaster" }
	| { kind: "failed"; error: string };

export type OtherDeployment = {
	deployment: Deployment;
	reading: Reading;
	retry: () => void;
};

/**
 * The tenant on every other configured deployment (openspec G6), read through each chain's own read
 * path — the platform relay where the console has the platform API. Re-read with every console
 * refresh. Shared by the card below and the suspend and resume dialogs, which name the chains where
 * the tenant is still enabled or disabled.
 */
export function useOtherDeployments(
	tenantId: string | undefined,
	lastUpdated: Date | undefined,
): OtherDeployment[] {
	const { deployment: current } = useConsole();
	const { session, expire } = usePlatform();
	const { platformApi, deployments } = getAdminConfig();
	const token = session?.token;
	const others = useMemo(
		() =>
			deployments.filter(
				(candidate) => deploymentKey(candidate) !== deploymentKey(current),
			),
		[deployments, current],
	);
	const [readings, setReadings] = useState<Record<string, Reading>>({});

	// One client per deployment, built once rather than on every poll. As the console's own read
	// client does, each reads the current session token per request, so a renewed session keeps them.
	const currentToken = useRef(token);
	currentToken.current = token;
	const onUnauthorized = useRef(expire);
	onUnauthorized.current = expire;
	const signedIn = token !== undefined;
	const clients = useMemo(
		() =>
			new Map(
				others.map((deployment) => [
					deploymentKey(deployment),
					deployment.sponsorshipPaymaster
						? new GianoPaymasterClient({
								address: deployment.sponsorshipPaymaster,
								publicClient: createReadClient(
									deployment,
									signedIn
										? {
												token: () => currentToken.current ?? "",
												onUnauthorized: (refused) =>
													onUnauthorized.current(refused),
											}
										: undefined,
								),
							})
						: undefined,
				]),
			),
		[others, signedIn],
	);

	const readOne = useCallback(
		async (deployment: Deployment): Promise<Reading> => {
			const client = clients.get(deploymentKey(deployment));
			if (!client || !tenantId) return { kind: "no-paymaster" };
			try {
				return { kind: "registered", tenant: await client.getTenant(tenantId) };
			} catch (cause) {
				const error = describeError(cause);
				return /is not registered/.test(error)
					? { kind: "not-registered" }
					: { kind: "failed", error };
			}
		},
		[tenantId, clients],
	);

	const read = useCallback(
		async (deployment: Deployment) => {
			const key = deploymentKey(deployment);
			setReadings((previous) =>
				previous[key] ? previous : { ...previous, [key]: { kind: "loading" } },
			);
			const reading = await readOne(deployment);
			setReadings((previous) => ({ ...previous, [key]: reading }));
		},
		[readOne],
	);

	// biome-ignore lint/correctness/useExhaustiveDependencies: `lastUpdated` is a trigger: re-read with every console refresh
	useEffect(() => {
		if (!tenantId || (platformApi && !token)) return;
		for (const deployment of others) void read(deployment);
	}, [others, read, tenantId, platformApi, token, lastUpdated]);

	return others.map((deployment) => ({
		deployment,
		reading: readings[deploymentKey(deployment)] ?? { kind: "loading" },
		retry: () => void read(deployment),
	}));
}

/**
 * The tenant on every other configured deployment: whether it is registered and enabled there, and
 * wallet-api's ledger balance for that chain. Writes there need the console switched to that
 * deployment, with a wallet on that chain.
 */
export function OtherDeployments({
	others,
	ledger,
}: {
	others: readonly OtherDeployment[];
	ledger: TenantDetail["ledger"] | undefined;
}) {
	if (others.length === 0) return null;
	return (
		<SectionCard
			title="Other deployments"
			subtitle="This tenant on every other chain this console is configured for. To act there, switch the console to that deployment."
		>
			<Table.ScrollArea>
				<Table.Root size="sm">
					<Table.Header>
						<Table.Row>
							<Table.ColumnHeader>Deployment</Table.ColumnHeader>
							<Table.ColumnHeader>On chain</Table.ColumnHeader>
							<Table.ColumnHeader textAlign="end">Balance</Table.ColumnHeader>
							<Table.ColumnHeader textAlign="end">
								Ledger balance
							</Table.ColumnHeader>
						</Table.Row>
					</Table.Header>
					<Table.Body>
						{others.map((other) => (
							<OtherRow
								key={deploymentKey(other.deployment)}
								other={other}
								ledger={ledger?.find(
									(row) => row.chainId === other.deployment.chainId,
								)}
							/>
						))}
					</Table.Body>
				</Table.Root>
			</Table.ScrollArea>
		</SectionCard>
	);
}

function OtherRow({
	other: { deployment, reading, retry },
	ledger,
}: {
	other: OtherDeployment;
	ledger: TenantDetail["ledger"][number] | undefined;
}) {
	const money = (wei: bigint) =>
		`${amount(wei, deployment.nativeCurrency)} ${deployment.nativeCurrency.symbol}`;
	return (
		<Table.Row data-testid={`other-deployment-${deployment.chainId}`}>
			<Table.Cell>
				<Text fontWeight="medium">{deployment.name}</Text>
				<Text fontSize="xs" color="fg.muted">
					chain {deployment.chainId}
				</Text>
			</Table.Cell>
			<Table.Cell>
				{reading.kind === "loading" && <Spinner size="xs" />}
				{reading.kind === "registered" && (
					<OnChainBadge
						state={reading.tenant.enabled ? "enabled" : "disabled"}
					/>
				)}
				{reading.kind === "not-registered" && (
					<OnChainBadge state="not-registered" />
				)}
				{reading.kind === "no-paymaster" && (
					<Text fontSize="xs" color="fg.muted">
						no paymaster configured
					</Text>
				)}
				{reading.kind === "failed" && (
					<HStack gap="2">
						<Text fontSize="xs" color="red.fg">
							not read: {reading.error.split("\n")[0]}
						</Text>
						<Button size="xs" variant="ghost" onClick={retry}>
							Try again
						</Button>
					</HStack>
				)}
			</Table.Cell>
			<Table.Cell textAlign="end" fontFamily="mono" fontSize="xs">
				{reading.kind === "registered" ? money(reading.tenant.balance) : "—"}
			</Table.Cell>
			<Table.Cell textAlign="end" fontFamily="mono" fontSize="xs">
				{ledger ? (
					<Stack gap="0" align="flex-end">
						<span>{money(BigInt(ledger.balanceWei))}</span>
						{ledger.lastSyncedBlock && (
							<Text color="fg.muted">at block {ledger.lastSyncedBlock}</Text>
						)}
					</Stack>
				) : (
					"—"
				)}
			</Table.Cell>
		</Table.Row>
	);
}
