import {
	Badge,
	Button,
	HStack,
	Popover,
	Portal,
	Stack,
	Text,
} from "@chakra-ui/react";
import { LuExternalLink } from "react-icons/lu";
import { amount, exactAmount } from "../lib/format";
import { addressNames, useConsole } from "../shell/ConsoleContext";
import { Copyable } from "./ui";

/**
 * An address in full, copyable, with every name the console knows for it (openspec D9): a
 * configured label such as *Safe · 3 of 5*, *the timelock*, *the paymaster*, *you*. With an
 * explorer configured, it links there too.
 */
export function AddressLabel({
	address,
	label,
}: {
	address: string;
	/** What the address is in this place, for the copy control's accessible name. */
	label?: string;
}) {
	const context = useConsole();
	const names = addressNames(address, context);
	const { explorerUrl } = context.deployment;
	return (
		<HStack gap="1.5" flexWrap="wrap" align="center">
			{names.map((name) => (
				<Badge
					key={name}
					colorPalette={name === "you" ? "brand" : "gray"}
					variant="subtle"
				>
					{name}
				</Badge>
			))}
			<Copyable value={address} label={label ?? names[0]} />
			{explorerUrl && (
				<ExplorerLink
					href={`${explorerUrl}/address/${address}`}
					what="address"
				/>
			)}
		</HStack>
	);
}

/** A transaction hash in full and copyable, linked to the explorer when one is configured. */
export function TxLink({ hash }: { hash: string }) {
	const { explorerUrl } = useConsole().deployment;
	return (
		<HStack gap="1.5" align="center">
			<Copyable value={hash} label="Transaction" />
			{explorerUrl && (
				<ExplorerLink href={`${explorerUrl}/tx/${hash}`} what="transaction" />
			)}
		</HStack>
	);
}

function ExplorerLink({ href, what }: { href: string; what: string }) {
	return (
		<a
			href={href}
			target="_blank"
			rel="noreferrer noopener"
			aria-label={`Open the ${what} in the explorer`}
			title="Open in the explorer"
		>
			<LuExternalLink aria-hidden="true" />
		</a>
	);
}

/**
 * An amount in the chain's currency, rounded for reading, with the exact figure one click away and
 * copyable (openspec C11). Not in a `title`: a tooltip cannot be selected, copied or reached by
 * keyboard, and the exact figure is the one an operator pastes into an incident.
 */
export function Amount({ wei, decimals }: { wei: bigint; decimals?: number }) {
	const { nativeCurrency } = useConsole().deployment;
	const exact = exactAmount(wei, nativeCurrency);
	return (
		<Popover.Root
			positioning={{ placement: "bottom-start" }}
			lazyMount
			unmountOnExit
		>
			<Popover.Trigger asChild>
				<Button
					variant="plain"
					size="sm"
					height="auto"
					minW="0"
					px="0"
					fontFamily="mono"
					fontWeight="inherit"
					fontSize="inherit"
					aria-label={`${exact}; show the exact amount`}
				>
					{amount(wei, nativeCurrency, decimals)} {nativeCurrency.symbol}
				</Button>
			</Popover.Trigger>
			<Portal>
				<Popover.Positioner>
					<Popover.Content width="auto">
						<Popover.Body>
							<Stack gap="1">
								<Text fontSize="xs" color="fg.muted">
									Exact amount
								</Text>
								<Copyable value={exact} label="Exact amount" />
							</Stack>
						</Popover.Body>
					</Popover.Content>
				</Popover.Positioner>
			</Portal>
		</Popover.Root>
	);
}
