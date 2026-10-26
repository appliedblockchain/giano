import { Alert, Box, Button, HStack, Stack, Text } from "@chakra-ui/react";
import { useState } from "react";
import { LuLogIn } from "react-icons/lu";
import { Copyable, SectionCard } from "../components/ui";
import { type SignInFailure, usePlatform } from "../lib/platform-session";
import type { PlatformAreaProps } from "./PlatformArea";

/**
 * The Platform area without a session (specs/PLATFORM-ADMIN-SPECS.md §11.3): one button that
 * connects the wallet if needed, then signs the message wallet-api issued. A refusal in the wallet
 * is the platform admin changing their mind, not an error.
 */
const FAILURE_TEXT: Record<
	Exclude<SignInFailure, "rejected" | "failed">,
	{ title: string; description: string }
> = {
	"not-admin": {
		title: "Not a platform admin on this deployment",
		description:
			"The connected address is not on this deployment's platform admin list. Connect the wallet holding a platform admin address, or ask a platform admin to add yours under Platform → Admins.",
	},
	disabled: {
		title: "Platform API disabled on this deployment",
		description:
			"wallet-api answers, but this environment has no platform sign-in domain, so there is nothing to sign in to.",
	},
};

export function SignIn({
	deployment,
	wallet,
	connect,
	connecting,
}: PlatformAreaProps) {
	const { signIn, endedNotice } = usePlatform();
	const [busy, setBusy] = useState(false);
	const [failure, setFailure] = useState<{
		title: string;
		description: string;
	}>();

	const start = async () => {
		setFailure(undefined);
		const signer = wallet ?? (await connect());
		if (!signer) return;
		setBusy(true);
		try {
			const result = await signIn(signer, deployment.chainId);
			if (result.ok || result.reason === "rejected") return;
			setFailure(
				result.reason === "failed"
					? {
							title: "Sign-in failed",
							description:
								result.message ?? "The platform API refused the request.",
						}
					: FAILURE_TEXT[result.reason],
			);
		} finally {
			setBusy(false);
		}
	};

	return (
		<SectionCard
			title="Platform admin sign-in"
			subtitle="Tenant administration is for Giano's platform admins. Sign in with the wallet that holds your platform admin address."
		>
			<Stack gap="4" maxW="2xl">
				{endedNotice && (
					<Alert.Root status="info" size="sm">
						<Alert.Indicator />
						<Alert.Content>
							<Alert.Description>{endedNotice}</Alert.Description>
						</Alert.Content>
					</Alert.Root>
				)}
				{failure && (
					<Alert.Root status="warning" size="sm">
						<Alert.Indicator />
						<Alert.Content>
							<Alert.Title>{failure.title}</Alert.Title>
							<Alert.Description>{failure.description}</Alert.Description>
						</Alert.Content>
					</Alert.Root>
				)}
				<Text fontSize="sm" color="fg.muted">
					Your wallet is asked to sign a message naming this console's domain.
					Nothing is sent on-chain and no gas is spent. The session lasts until
					it expires, you sign out, reload, or change account, network or
					deployment.
				</Text>
				<Box>
					<Button
						colorPalette="brand"
						onClick={() => void start()}
						loading={busy || connecting}
						loadingText={connecting ? "Connecting" : "Waiting for signature"}
					>
						<LuLogIn /> Sign in with wallet
					</Button>
				</Box>
				{wallet && (
					<HStack gap="2">
						<Text fontSize="xs" color="fg.muted">
							Signing as
						</Text>
						<Copyable value={wallet.address} label="Connected account" />
					</HStack>
				)}
			</Stack>
		</SectionCard>
	);
}
