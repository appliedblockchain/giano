import {
	Alert,
	Badge,
	Box,
	Button,
	HStack,
	Stack,
	Text,
} from "@chakra-ui/react";
import type { ReactNode } from "react";
import { LuClock } from "react-icons/lu";
import { relativeTime } from "../lib/proposals";
import type { QueuedKey } from "../lib/queued";
import { Link, TAB_PATHS } from "../lib/router";
import { useConsole } from "../shell/ConsoleContext";

export type StatusTone = "green" | "orange" | "red" | "gray";

/** A coloured dot and the words for it: never colour alone. */
export function StatusText({
	tone,
	children,
}: {
	tone: StatusTone;
	children: ReactNode;
}) {
	return (
		<HStack as="span" gap="1.5" display="inline-flex">
			<Box boxSize="2" rounded="full" bg={`${tone}.solid`} aria-hidden="true" />
			<Text as="span">{children}</Text>
		</HStack>
	);
}

/** Marks something that waits out the timelock's delay: the timelock's purple, with a clock. */
export function TimelockedTag({
	children = "timelocked",
}: {
	children?: ReactNode;
}) {
	return (
		<Badge colorPalette="timelock" variant="subtle" gap="1">
			<LuClock aria-hidden="true" />
			{children}
		</Badge>
	);
}

/**
 * A change the timelock will make here, shown where it will land (openspec N7): what it changes to,
 * when it can execute, and a link to the operation. Renders nothing when nothing is queued for
 * `keys`, so it can sit beside any value unconditionally.
 */
export function QueuedMarker({
	keys,
}: {
	keys: QueuedKey | readonly QueuedKey[];
}) {
	const { timelockOperations } = useConsole();
	const wanted = typeof keys === "string" ? [keys] : keys;
	const changes = timelockOperations.changes.filter((change) =>
		wanted.includes(change.key),
	);
	if (changes.length === 0) return null;

	return (
		<Stack gap="1">
			{changes.map((change) => (
				<Link
					key={`${change.operationId}:${change.key}`}
					to={`${TAB_PATHS.timelock}#${change.operationId}`}
					display="inline-flex"
					alignItems="center"
					gap="1.5"
					fontSize="xs"
					color="timelock.fg"
					_hover={{ textDecoration: "underline" }}
				>
					<LuClock aria-hidden="true" />
					<Text as="span">
						Queued: {change.summary} ·{" "}
						{change.state === "ready"
							? "ready now"
							: change.readyAt
								? `ready ${relativeTime(change.readyAt)}`
								: "waiting"}
					</Text>
				</Link>
			))}
		</Stack>
	);
}

/**
 * A failure stated where it happened (openspec C6). A read that failed offers to try again, and the
 * caller shows no spinner after it: a spinner under an error says the opposite of the error.
 */
export function InlineError({
	title,
	error,
	retry,
	retrying,
	stale,
}: {
	title: string;
	error: string;
	retry?: () => void;
	retrying?: boolean;
	/** True when the last good data is still on screen under this error. */
	stale?: boolean;
}) {
	return (
		<Alert.Root status="error">
			<Alert.Indicator />
			<Alert.Content>
				<Alert.Title>{title}</Alert.Title>
				<Alert.Description overflowWrap="anywhere">
					{error}
					{stale && " What is shown below is from the last read that worked."}
				</Alert.Description>
			</Alert.Content>
			{retry && (
				<Button
					size="xs"
					variant="outline"
					alignSelf="center"
					onClick={retry}
					loading={retrying}
				>
					Try again
				</Button>
			)}
		</Alert.Root>
	);
}
