import type {
	HealthReport,
	PaymasterOverview,
} from "@appliedblockchain/giano-paymaster-sdk";
import {
	Badge,
	Box,
	Button,
	Container,
	Heading,
	HStack,
	NativeSelect,
	Popover,
	Portal,
	Stack,
	Text,
} from "@chakra-ui/react";
import { useEffect, useState } from "react";
import {
	LuLogOut,
	LuMoon,
	LuRefreshCw,
	LuSun,
	LuUnplug,
	LuWallet,
} from "react-icons/lu";
import { Copyable } from "../components/ui";
import { type Deployment, deploymentKey, getAdminConfig } from "../config";
import type { ConnectedWallet } from "../lib/chain";
import { useColorMode } from "../lib/color-mode";
import { usePlatform } from "../lib/platform-session";
import { Link, TAB_PATHS } from "../lib/router";

type HeaderProps = {
	deployment: Deployment;
	selectDeployment: (next: Deployment) => void;
	overview: PaymasterOverview | undefined;
	health: HealthReport | undefined;
	lastUpdated: Date | undefined;
	loading: boolean;
	refresh: () => Promise<void>;
	wallet: ConnectedWallet | undefined;
	roles: number;
	connect: () => Promise<unknown>;
	connecting: boolean;
	disconnect: () => Promise<void>;
};

/**
 * The console's header: which deployment and paymaster this is, who is signed in and with what
 * wallet, and a one-line status of the deployment under it — the things an operator has to be sure
 * of before acting, on every page.
 */
export function Header(props: HeaderProps) {
	const { deployment, overview } = props;
	return (
		<Box
			as="header"
			borderBottomWidth="1px"
			bg="surface"
			position="sticky"
			top="0"
			zIndex="docked"
		>
			<Container maxW="7xl" py="3">
				<HStack justify="space-between" gap="4" flexWrap="wrap">
					<HStack gap="3" flexWrap="wrap">
						<Box
							aria-hidden="true"
							boxSize="8"
							rounded="md"
							bg="brand.solid"
							color="brand.contrast"
							display="grid"
							placeItems="center"
							fontWeight="semibold"
						>
							G
						</Box>
						<Heading as="h1" size="md">
							Giano console
						</Heading>
						<DeploymentPicker {...props} />
					</HStack>

					<HStack gap="2" flexWrap="wrap">
						<SessionPill />
						{props.wallet ? (
							<WalletCard
								wallet={props.wallet}
								deployment={deployment}
								roles={props.roles}
								disconnect={props.disconnect}
							/>
						) : (
							<Button
								size="sm"
								colorPalette="brand"
								onClick={() => void props.connect()}
								loading={props.connecting}
								loadingText="Connecting"
							>
								<LuWallet /> Connect wallet
							</Button>
						)}
						<ColorModeButton />
					</HStack>
				</HStack>
				{overview && <StatusLine {...props} overview={overview} />}
			</Container>
		</Box>
	);
}

function DeploymentPicker({ deployment, selectDeployment }: HeaderProps) {
	const { deployments } = getAdminConfig();
	if (deployments.length === 1)
		return (
			<Badge colorPalette="brand" variant="subtle">
				{deployment.name} · chain {deployment.chainId}
			</Badge>
		);
	return (
		<NativeSelect.Root size="sm" width="auto">
			<NativeSelect.Field
				value={deploymentKey(deployment)}
				onChange={(event) => {
					const next = deployments.find(
						(candidate) =>
							deploymentKey(candidate) === event.currentTarget.value,
					);
					if (next) selectDeployment(next);
				}}
				aria-label="Deployment"
			>
				{deployments.map((candidate) => (
					<option
						key={deploymentKey(candidate)}
						value={deploymentKey(candidate)}
					>
						{candidate.name} — chain {candidate.chainId}
					</option>
				))}
			</NativeSelect.Field>
			<NativeSelect.Indicator />
		</NativeSelect.Root>
	);
}

/**
 * Health, the invariant and freshness, in one line under the header: enough to know whether to look
 * further, on every page, without opening the Health tab.
 */
function StatusLine({
	overview,
	health,
	lastUpdated,
	loading,
	refresh,
}: HeaderProps & { overview: PaymasterOverview }) {
	const problems = health?.checks.filter((check) => check.level !== "ok") ?? [];
	const failures = problems.filter((check) => check.level === "fail").length;
	const warnings = problems.length - failures;
	const healthText =
		failures > 0
			? `${failures} failing check${failures === 1 ? "" : "s"}`
			: warnings > 0
				? `${warnings} warning${warnings === 1 ? "" : "s"}`
				: "all checks pass";
	const healthTone = failures > 0 ? "red" : warnings > 0 ? "orange" : "green";

	return (
		<HStack
			gap="4"
			mt="2"
			fontSize="sm"
			color="fg.muted"
			flexWrap="wrap"
			aria-label="Deployment status"
		>
			<Field label="Paymaster" value={overview.address} />
			{health && (
				<Link to={TAB_PATHS.health} color="fg.muted" _hover={{ color: "fg" }}>
					<StatusText tone={healthTone}>{healthText}</StatusText>
				</Link>
			)}
			<StatusText tone={overview.solvency.holds ? "green" : "red"}>
				{overview.solvency.holds ? "invariant holds" : "invariant breached"}
			</StatusText>
			{overview.config.paused && (
				<StatusText tone="red">paused, sponsoring nothing</StatusText>
			)}
			<HStack gap="1" ms="auto">
				{lastUpdated && (
					<Text fontSize="xs">updated {lastUpdated.toLocaleTimeString()}</Text>
				)}
				<Button
					size="xs"
					variant="ghost"
					onClick={() => void refresh()}
					loading={loading}
					aria-label="Refresh"
				>
					<LuRefreshCw />
				</Button>
			</HStack>
		</HStack>
	);
}

/** A coloured dot and the words for it: never colour alone. */
function StatusText({
	tone,
	children,
}: {
	tone: "green" | "orange" | "red";
	children: string;
}) {
	return (
		<HStack gap="1.5">
			<Box boxSize="2" rounded="full" bg={`${tone}.solid`} aria-hidden="true" />
			<Text as="span">{children}</Text>
		</HStack>
	);
}

/** Re-renders every `ms`, for a countdown. */
export function useNow(ms: number): number {
	const [now, setNow] = useState(Date.now);
	useEffect(() => {
		const timer = setInterval(() => setNow(Date.now()), ms);
		return () => clearInterval(timer);
	}, [ms]);
	return now;
}

/**
 * Who is signed in and for how long, with the way out — where the platform API is configured. In
 * minutes rather than a clock time: what an operator wants to know is whether to sign again before
 * starting something.
 */
function SessionPill() {
	const { session, signOut } = usePlatform();
	const now = useNow(15_000);
	if (!session) return null;
	const minutes = Math.max(
		0,
		Math.ceil((session.expiresAt.getTime() - now) / 60_000),
	);
	return (
		<Popover.Root
			positioning={{ placement: "bottom-end" }}
			lazyMount
			unmountOnExit
		>
			<Popover.Trigger asChild>
				<Button size="sm" variant="outline" aria-label="Platform admin session">
					<Badge colorPalette="brand" variant="solid">
						admin
					</Badge>
					{session.admin.id}
					<Text as="span" color="fg.muted" fontWeight="normal">
						· {minutes} min left
					</Text>
				</Button>
			</Popover.Trigger>
			<Portal>
				<Popover.Positioner>
					<Popover.Content width="auto" maxW="md">
						<Popover.Arrow />
						<Popover.Body>
							<Stack gap="3">
								<Field label="Platform admin" value={session.admin.address} />
								<Text fontSize="sm">
									Signed in as {session.admin.id} until{" "}
									{session.expiresAt.toLocaleTimeString()}.
								</Text>
								<Box>
									<Button
										size="sm"
										variant="outline"
										onClick={() => void signOut()}
									>
										<LuLogOut /> Sign out
									</Button>
								</Box>
							</Stack>
						</Popover.Body>
					</Popover.Content>
				</Popover.Positioner>
			</Portal>
		</Popover.Root>
	);
}

function ColorModeButton() {
	const { colorMode, toggleColorMode } = useColorMode();
	// A toggle, named for what it turns on: not "Switch to …", which in this header means a network.
	return (
		<Button
			size="sm"
			variant="ghost"
			onClick={toggleColorMode}
			aria-label="Dark mode"
			aria-pressed={colorMode === "dark"}
		>
			{colorMode === "dark" ? <LuSun /> : <LuMoon />}
		</Button>
	);
}

/**
 * A value with the word for what it is.
 *
 * Two bare hex strings sat in this header — the paymaster and the connected account — and nothing
 * said which was which. They are the same shape, they are both copyable, and getting them the wrong
 * way round is exactly the mistake a operator cannot afford to make.
 */
function Field({ label, value }: { label: string; value: string }) {
	return (
		<HStack gap="2">
			<Text
				fontSize="2xs"
				color="fg.muted"
				textTransform="uppercase"
				letterSpacing="wide"
				fontWeight="medium"
			>
				{label}
			</Text>
			<Copyable value={value} label={label} />
		</HStack>
	);
}

/**
 * What the console is signing as.
 *
 * Occupies the same slot and about the same width as the connect button it replaces. An account
 * address is 42 characters and is never abbreviated here — see {@link Copyable} — so shown inline
 * it wraps the header onto a second row the moment a wallet connects, and every control in it
 * moves. It goes in a panel instead: the button carries the state worth seeing at a glance, and
 * the values a operator actually reads are one click away and full width.
 *
 * The network is named there even though a connected wallet is always on the deployment's chain —
 * that it agrees is the thing worth showing, and it is the half a operator with several
 * environments open will otherwise assume.
 */
function WalletCard({
	wallet,
	deployment,
	roles,
	disconnect,
}: {
	wallet: ConnectedWallet;
	deployment: Deployment;
	roles: number;
	disconnect: () => Promise<void>;
}) {
	const { session } = usePlatform();
	return (
		<Popover.Root
			positioning={{ placement: "bottom-end" }}
			lazyMount
			unmountOnExit
		>
			<Popover.Trigger asChild>
				<Button size="sm" variant="outline">
					<Box boxSize="2" rounded="full" bg="green.solid" aria-hidden="true" />
					Connected
					<Badge colorPalette={roles > 0 ? "green" : "gray"} variant="subtle">
						{roles > 0 ? `${roles} role${roles === 1 ? "" : "s"}` : "no roles"}
					</Badge>
				</Button>
			</Popover.Trigger>
			<Portal>
				<Popover.Positioner>
					<Popover.Content width="auto" maxW="md">
						<Popover.Arrow />
						<Popover.Body>
							<Stack gap="3">
								<Field label="Account" value={wallet.address} />
								<HStack gap="2">
									<Text
										fontSize="2xs"
										color="fg.muted"
										textTransform="uppercase"
										letterSpacing="wide"
										fontWeight="medium"
									>
										Network
									</Text>
									<Text fontSize="sm">
										{deployment.name} · chain {deployment.chainId}
									</Text>
								</HStack>
								<HStack gap="2">
									<Text
										fontSize="2xs"
										color="fg.muted"
										textTransform="uppercase"
										letterSpacing="wide"
										fontWeight="medium"
									>
										Roles
									</Text>
									<Text fontSize="sm">
										{roles > 0
											? `${roles} on this paymaster`
											: "none on this paymaster — reads only"}
									</Text>
								</HStack>
								<Box>
									<Button
										size="sm"
										variant="outline"
										onClick={() => void disconnect()}
									>
										<LuUnplug />{" "}
										{session ? "Disconnect and sign out" : "Disconnect"}
									</Button>
								</Box>
							</Stack>
						</Popover.Body>
					</Popover.Content>
				</Popover.Positioner>
			</Portal>
		</Popover.Root>
	);
}
