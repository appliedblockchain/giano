import { Box, Button, HStack, Stack, Text } from "@chakra-ui/react";
import { useState } from "react";
import { LuClock } from "react-icons/lu";
import type { ConnectedWallet } from "../lib/chain";
import { usePlatform } from "../lib/platform-session";
import { useNow } from "./Header";

const WARN_MS = 2 * 60_000;

/**
 * Two minutes before the platform admin session ends, a card that says so and offers to sign again
 * (openspec platform-console-access). Without it a session ended mid-task, taking any half-typed
 * dialog with it. "Stay signed in" signs a fresh challenge and swaps the session in place — nothing
 * on the page is remounted, so whatever the operator was typing stays.
 */
export function SessionWarning({
	wallet,
	connect,
	chainId,
}: {
	wallet: ConnectedWallet | undefined;
	connect: () => Promise<ConnectedWallet | undefined>;
	chainId: number;
}) {
	const { session, signIn, signOut } = usePlatform();
	const now = useNow(5_000);
	const [busy, setBusy] = useState(false);
	if (!session) return null;
	const left = session.expiresAt.getTime() - now;
	if (left > WARN_MS) return null;

	const stay = async () => {
		setBusy(true);
		try {
			const signer = wallet ?? (await connect());
			if (signer) await signIn(signer, chainId);
		} finally {
			setBusy(false);
		}
	};

	const minutes = Math.max(1, Math.ceil(left / 60_000));
	return (
		<Box
			role="status"
			position="fixed"
			insetEnd="4"
			bottom="4"
			zIndex="toast"
			maxW="sm"
			bg="surface"
			borderWidth="1px"
			rounded="lg"
			shadow="lg"
			p="4"
		>
			<Stack gap="2">
				<HStack gap="2" color="orange.fg">
					<LuClock aria-hidden="true" />
					<Text fontWeight="semibold" color="fg">
						Your session ends in {minutes} minute{minutes === 1 ? "" : "s"}
					</Text>
				</HStack>
				<Text fontSize="sm" color="fg.muted">
					Sign again to keep working. Anything you are typing stays where it is.
				</Text>
				<HStack gap="2">
					<Button
						size="sm"
						colorPalette="brand"
						onClick={() => void stay()}
						loading={busy}
						loadingText="Waiting for signature"
					>
						Stay signed in
					</Button>
					<Button size="sm" variant="outline" onClick={() => void signOut()}>
						Sign out
					</Button>
				</HStack>
			</Stack>
		</Box>
	);
}
