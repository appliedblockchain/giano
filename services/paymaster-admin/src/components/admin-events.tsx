import type {
	AdminEvent,
	BlockRange,
	GianoPaymasterClient,
} from "@appliedblockchain/giano-paymaster-sdk";
import { HStack, Stack, Text } from "@chakra-ui/react";
import { useCallback, useMemo } from "react";
import { LuClock } from "react-icons/lu";
import { useWindows } from "../hooks/useWindows";
import {
	describeAdminEvent,
	type Namer,
	shortAddress,
} from "../lib/admin-events";
import { amount } from "../lib/format";
import { addressNames, useConsole } from "../shell/ConsoleContext";
import { AddressLabel, TxLink } from "./values";

/**
 * The paymaster's admin events (B1), a window of blocks at a time: the timelock's too when the
 * deployment names one. `tenantId` narrows them to one tenant.
 */
export function useAdminEvents(
	client: GianoPaymasterClient,
	trigger: unknown,
	tenantId?: string,
) {
	const { deployment } = useConsole();
	const timelock = deployment.timelockAddress;
	const read = useCallback(
		async (range?: Partial<BlockRange>) => {
			const { events, ...page } = await client.getAdminEvents({
				range,
				timelock,
				tenantId,
			});
			return { ...page, items: events };
		},
		[client, timelock, tenantId],
	);
	const head = useCallback(
		() => client.publicClient.getBlockNumber(),
		[client],
	);
	return useWindows(read, head, trigger);
}

/** How the console names things in an event's sentence. */
export function useNamer(tenantName: (uuid: string) => string): Namer {
	const context = useConsole();
	const { nativeCurrency } = context.deployment;
	return useMemo(
		() => ({
			address: (address: string) =>
				shortAddress(address, addressNames(address, context)),
			tenant: tenantName,
			money: (wei: bigint) =>
				`${amount(wei, nativeCurrency, 6)} ${nativeCurrency.symbol}`,
			time: (unix: number) => new Date(unix * 1000).toLocaleString(),
		}),
		[context, nativeCurrency, tenantName],
	);
}

/** Admin events, newest first: what was done, when, by whom, and the transaction. */
export function AdminEventList({
	events,
	namer,
}: {
	events: readonly AdminEvent[];
	namer: Namer;
}) {
	return (
		<Stack gap="0" data-testid="admin-events">
			{events.map((event, index) => (
				<HStack
					key={`${event.transactionHash}:${event.source}:${event.logIndex}`}
					justify="space-between"
					align="flex-start"
					gap="4"
					py="3"
					flexWrap="wrap"
					borderTopWidth={index === 0 ? "0" : "1px"}
					data-testid={`admin-event-${event.kind}`}
				>
					<Stack gap="1" minW="0" flex="1">
						<HStack gap="1.5" align="flex-start">
							{event.source === "timelock" && (
								<Text
									as="span"
									color="timelock.fg"
									pt="0.5"
									aria-label="timelock"
								>
									<LuClock aria-hidden="true" />
								</Text>
							)}
							<Text fontSize="sm" wordBreak="break-word">
								{describeAdminEvent(event, namer)}
							</Text>
						</HStack>
						<HStack gap="2" fontSize="xs" color="fg.muted" flexWrap="wrap">
							<Text>
								{event.blockTime
									? new Date(event.blockTime * 1000).toLocaleString()
									: "time unknown"}
							</Text>
							<Text fontFamily="mono">
								block {event.blockNumber.toString()}
							</Text>
							{event.actor && (
								<HStack gap="1.5">
									<Text>by</Text>
									<AddressLabel address={event.actor} label="By" />
								</HStack>
							)}
						</HStack>
					</Stack>
					<TxLink hash={event.transactionHash} />
				</HStack>
			))}
		</Stack>
	);
}
