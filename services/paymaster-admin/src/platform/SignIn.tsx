import {
	Alert,
	Box,
	Button,
	Heading,
	HStack,
	Stack,
	Text,
} from "@chakra-ui/react";
import { type ReactNode, useState } from "react";
import { LuCheck, LuLogIn } from "react-icons/lu";
import { Copyable } from "../components/ui";
import { type SignInFailure, usePlatform } from "../lib/platform-session";
import type { PlatformAreaProps } from "./shared";

/**
 * Either area without a session, where the console has the platform API (specs/PLATFORM-ADMIN-SPECS.md
 * §11.3; openspec platform-console-access): one button that connects the wallet if needed, then signs
 * the message wallet-api issued. A refusal in the wallet is the platform admin changing their mind,
 * not an error.
 *
 * It gates the Paymaster area too: there the console reads the chain through wallet-api's platform
 * relay, which serves nobody without a session — so the roster, balances and keyed RPC quota are not
 * one click away for anyone who finds the page.
 */
export type SignInProps = Pick<
	PlatformAreaProps,
	"deployment" | "wallet" | "connect" | "connecting"
>;

const FAILURE_TEXT: Record<
	Exclude<SignInFailure, "rejected" | "failed">,
	{ title: string; description: string }
> = {
	"not-admin": {
		title: "Not a platform admin on this deployment",
		description:
			"The connected address is not on this deployment's platform admin list. Connect the wallet holding a platform admin address, or ask a platform admin to add yours under Admins.",
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
}: SignInProps) {
	const { signIn, endedNotice, disabled } = usePlatform();
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

	const connected = wallet !== undefined;
	return (
		<Box
			maxW="lg"
			mx="auto"
			mt={{ base: "4", md: "10" }}
			bg="surface"
			borderWidth="1px"
			rounded="xl"
			p={{ base: "5", md: "7" }}
		>
			<Stack gap="5">
				<Stack gap="1.5">
					<Heading as="h2" size="xl">
						Sign in
					</Heading>
					<Text fontSize="sm" color="fg.muted">
						This console reads nothing until a platform admin signs in. Your
						wallet signs a message that names this console's domain; no
						transaction is sent and no gas is spent.
					</Text>
				</Stack>
				{endedNotice && (
					<Alert.Root status="info" size="sm">
						<Alert.Indicator />
						<Alert.Content>
							<Alert.Description>{endedNotice}</Alert.Description>
						</Alert.Content>
					</Alert.Root>
				)}
				{disabled && (
					<Alert.Root status="warning" size="sm">
						<Alert.Indicator />
						<Alert.Content>
							<Alert.Title>{FAILURE_TEXT.disabled.title}</Alert.Title>
							<Alert.Description>
								{FAILURE_TEXT.disabled.description}
							</Alert.Description>
						</Alert.Content>
					</Alert.Root>
				)}
				{failure && !disabled && (
					<Alert.Root status="warning" size="sm">
						<Alert.Indicator />
						<Alert.Content>
							<Alert.Title>{failure.title}</Alert.Title>
							<Alert.Description>{failure.description}</Alert.Description>
						</Alert.Content>
					</Alert.Root>
				)}
				{!disabled && (
					<>
						<Stack as="ol" gap="3" listStyleType="none">
							<Step
								number={1}
								done={connected}
								title={connected ? "Wallet connected" : "Connect a wallet"}
							>
								{wallet ? (
									<HStack gap="2" flexWrap="wrap">
										<Copyable
											value={wallet.address}
											label="Connected account"
										/>
										<Text as="span">on {deployment.name}</Text>
									</HStack>
								) : (
									`The one holding your platform admin address, on ${deployment.name}.`
								)}
							</Step>
							<Step number={2} done={false} title="Sign the message">
								Only addresses on wallet-api's platform admin list get a
								session.
							</Step>
						</Stack>
						<Button
							colorPalette="brand"
							onClick={() => void start()}
							loading={busy || connecting}
							loadingText={connecting ? "Connecting" : "Waiting for signature"}
						>
							<LuLogIn /> Sign in with wallet
						</Button>
						<Text fontSize="xs" color="fg.muted">
							The session lives in this tab only, and the console warns you
							before it expires. Reloading, switching account or network, or
							changing deployment ends it.
						</Text>
					</>
				)}
			</Stack>
		</Box>
	);
}

function Step({
	number,
	done,
	title,
	children,
}: {
	number: number;
	done: boolean;
	title: string;
	children: ReactNode;
}) {
	return (
		<HStack as="li" gap="3" align="flex-start">
			<Box
				aria-hidden="true"
				boxSize="6"
				flexShrink="0"
				rounded="full"
				display="grid"
				placeItems="center"
				fontSize="xs"
				fontWeight="bold"
				bg={done ? "green.solid" : undefined}
				color={done ? "green.contrast" : "brand.fg"}
				borderWidth={done ? undefined : "2px"}
				borderColor="brand.solid"
			>
				{done ? <LuCheck /> : number}
			</Box>
			<Stack gap="0.5">
				<Text fontSize="sm" fontWeight="semibold">
					{title}
				</Text>
				<Box fontSize="sm" color="fg.muted">
					{children}
				</Box>
			</Stack>
		</HStack>
	);
}
