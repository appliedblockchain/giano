import type {
	GianoTimelockClient,
	HealthReport,
} from "@appliedblockchain/giano-paymaster-sdk";
import {
	Alert,
	Box,
	Button,
	Container,
	Heading,
	HStack,
	Spinner,
	Stack,
	Text,
} from "@chakra-ui/react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ProposalDialog } from "./components/ProposalDialog";
import { Copyable, notifyError } from "./components/ui";
import {
	type Deployment,
	deploymentKey,
	getAdminConfig,
	initialDeployment,
	rememberDeployment,
} from "./config";
import { usePaymaster } from "./hooks/usePaymaster";
import {
	ChainNotAddedError,
	type ConnectedWallet,
	connectOnChain,
	getAuthorisedAccount,
	getInjectedProvider,
	isUserRejection,
	networkDetails,
} from "./lib/chain";
import { PlatformSessionProvider, usePlatform } from "./lib/platform-session";
import type { ProposalRequest, Propose } from "./lib/proposals";
import { Link, type Route, TAB_PATHS, useRoute } from "./lib/router";
import { HealthPanel } from "./panels/HealthPanel";
import { HistoryPanel } from "./panels/HistoryPanel";
import { OverviewPanel } from "./panels/OverviewPanel";
import { RolesPanel } from "./panels/RolesPanel";
import { SettingsPanel } from "./panels/SettingsPanel";
import { TenantsPanel } from "./panels/TenantsPanel";
import { TimelockPanel } from "./panels/TimelockPanel";
import { AdminsTab } from "./platform/AdminsTab";
import { SignIn } from "./platform/SignIn";
import type { PlatformAreaProps } from "./platform/shared";
import { TenantsTab } from "./platform/TenantsTab";
import { Header } from "./shell/Header";
import { SessionWarning } from "./shell/SessionWarning";
import { TabBar } from "./shell/TabBar";

export function App() {
	const { deployments } = getAdminConfig();
	const [deployment, setDeployment] = useState(() =>
		initialDeployment(deployments),
	);

	const selectDeployment = useCallback((next: Deployment) => {
		setDeployment(next);
		rememberDeployment(next);
	}, []);

	// Keyed on the deployment: switching environments remounts the console under a fresh provider,
	// and the platform admin session and the connected wallet go with it. The wallet is bound to the
	// old chain and its roles were read from the old paymaster — keeping it would leave the console
	// offering actions an account may not hold on the deployment now on screen. Reconnecting is one
	// click and makes the chain check run again.
	return (
		<PlatformSessionProvider key={deploymentKey(deployment)}>
			<Console deployment={deployment} selectDeployment={selectDeployment} />
		</PlatformSessionProvider>
	);
}

function Console({
	deployment,
	selectDeployment: onSelectDeployment,
}: {
	deployment: Deployment;
	selectDeployment: (next: Deployment) => void;
}) {
	const { platformApi } = getAdminConfig();
	const { session, expire, signOut } = usePlatform();
	const [wallet, setWallet] = useState<ConnectedWallet>();
	const [connecting, setConnecting] = useState(false);
	const [notAdded, setNotAdded] = useState<ChainNotAddedError>();
	/**
	 * Set while the console is driving the wallet.
	 *
	 * Connecting can now include a network switch, which the wallet announces as `chainChanged` —
	 * and the listener below answers that by reloading, which would abandon the prompt the operator
	 * has just approved. Changes made in the wallet itself still reload, which is what it is for.
	 */
	const connectingRef = useRef(false);
	/**
	 * Where the platform API is configured, the chain is read through wallet-api's platform relay,
	 * with the platform admin session — and not at all before there is one. Without it, straight
	 * from each deployment's rpcUrl, as it always was.
	 */
	const readAuth = platformApi
		? session
			? { token: session.token, onUnauthorized: expire }
			: ("required" as const)
		: undefined;
	const {
		client,
		overview,
		health,
		myRoles,
		rosterOnChain,
		loading,
		error,
		lastUpdated,
		refresh,
	} = usePaymaster(deployment, wallet, readAuth);
	const signedOut = platformApi && !session;

	/**
	 * The paymaster's timelock, when the deployment names one (G9). Built from the paymaster client
	 * so it shares its connection and its wallet. With it, a timelocked action the wallet cannot send
	 * opens a proposal instead (`propose`); without it there is nothing to propose to.
	 */
	const timelock = useMemo(
		() =>
			client && deployment.timelockAddress
				? client.timelock(deployment.timelockAddress)
				: undefined,
		[client, deployment.timelockAddress],
	);
	const [proposal, setProposal] = useState<ProposalRequest>();
	const propose = timelock ? setProposal : undefined;

	const selectDeployment = useCallback(
		(next: Deployment) => {
			if (deploymentKey(next) === deploymentKey(deployment)) return;
			onSelectDeployment(next);
		},
		[deployment, onSelectDeployment],
	);

	// Restore a wallet the user already authorised, so a reload does not demand a fresh prompt.
	useEffect(() => {
		void getAuthorisedAccount(deployment)
			.then((restored) => restored && setWallet(restored))
			.catch(() => undefined);
	}, [deployment]);

	// A wallet that switches account or network mid-session would otherwise leave the console
	// signing as somebody it is no longer connected to.
	useEffect(() => {
		const provider = getInjectedProvider();
		if (!provider) return;
		// A switch the console itself asked for is finished by the connect flow, which rebinds the
		// client; reloading in the middle of that would throw away the prompt the operator just approved.
		const reload = () => {
			if (connectingRef.current) return;
			window.location.reload();
		};
		provider.on?.("accountsChanged", reload);
		provider.on?.("chainChanged", reload);
		return () => {
			provider.removeListener?.("accountsChanged", reload);
			provider.removeListener?.("chainChanged", reload);
		};
	}, []);

	/** Resolves to the wallet it connected, so a caller can act with it straight away (operator sign-in). */
	const connect = useCallback(async (): Promise<
		ConnectedWallet | undefined
	> => {
		setConnecting(true);
		setNotAdded(undefined);
		connectingRef.current = true;
		try {
			const connected = await connectOnChain(deployment);
			setWallet(connected);
			return connected;
		} catch (cause) {
			if (cause instanceof ChainNotAddedError) setNotAdded(cause);
			else if (!isUserRejection(cause))
				notifyError("Could not connect a wallet", cause);
			return undefined;
		} finally {
			connectingRef.current = false;
			setConnecting(false);
		}
	}, [deployment]);

	const disconnect = useCallback(async () => {
		// Best effort: a wallet that supports it forgets this site, so a reload does not reconnect it
		// silently. The console forgets the wallet either way. The session was signed by this wallet,
		// so it goes with it.
		await getInjectedProvider()
			?.request({
				method: "wallet_revokePermissions",
				params: [{ eth_accounts: {} }],
			} as never)
			.catch(() => undefined);
		setWallet(undefined);
		if (session) await signOut();
	}, [session, signOut]);

	const route = useRoute();
	const platformProps = {
		deployment,
		wallet,
		connect,
		connecting,
		client,
		overview,
		myRoles,
		refreshChain: refresh,
	};

	return (
		<Box minH="100vh">
			<Header
				deployment={deployment}
				selectDeployment={selectDeployment}
				overview={overview}
				health={health}
				lastUpdated={lastUpdated}
				loading={loading}
				refresh={refresh}
				wallet={wallet}
				roles={myRoles.length}
				connect={connect}
				connecting={connecting}
				disconnect={disconnect}
			/>

			<Container maxW="7xl" py="6">
				{!wallet && notAdded && (
					<Alert.Root status="warning" mb="4">
						<Alert.Indicator />
						<Alert.Content>
							<Alert.Title>
								Add {notAdded.deployment.name} in your wallet
							</Alert.Title>
							<Alert.Description>
								Your wallet would not take this network from the console. It
								said: {notAdded.walletMessage}
							</Alert.Description>
							<Stack gap="1" mt="3">
								{networkDetails(notAdded.deployment, notAdded.rpcUrl).map(
									({ label, value }) => (
										<HStack key={label} gap="3">
											<Text
												fontSize="xs"
												color="fg.muted"
												minW="28"
												textAlign="right"
											>
												{label}
											</Text>
											<Copyable value={value} label={label} />
										</HStack>
									),
								)}
							</Stack>
							<Text fontSize="xs" color="fg.muted" mt="2">
								Wallets generally accept only an HTTPS address, localhost or
								127.0.0.1 as an RPC URL. If yours will not take the address
								above, any address of your own that reaches the same node does
								just as well.
							</Text>
							<Box mt="3">
								<Button
									size="sm"
									colorPalette="brand"
									onClick={() => void connect()}
									loading={connecting}
									loadingText="Connecting"
								>
									Connect again
								</Button>
							</Box>
						</Alert.Content>
					</Alert.Root>
				)}

				{!wallet && !notAdded && !platformApi && (
					<Alert.Root status="info" mb="4">
						<Alert.Indicator />
						<Alert.Content>
							<Alert.Title>Read-only</Alert.Title>
							<Alert.Description>
								Everything here is read straight from the chain, so no wallet is
								needed to inspect a deployment. Connect one to act — the console
								never sees a key, it only asks your wallet to sign.
							</Alert.Description>
						</Alert.Content>
					</Alert.Root>
				)}

				{error && (
					<Alert.Root status="error" mb="4">
						<Alert.Indicator />
						<Alert.Content>
							<Alert.Title>Could not read the paymaster</Alert.Title>
							<Alert.Description>{error}</Alert.Description>
						</Alert.Content>
					</Alert.Root>
				)}

				{signedOut ? (
					<SignIn
						deployment={deployment}
						wallet={wallet}
						connect={connect}
						connecting={connecting}
					/>
				) : (
					<>
						<TabBar
							route={route}
							platformApi={platformApi}
							tenants={overview?.tenants.length}
							healthLevel={health?.level}
						/>
						<RouteView
							route={route}
							platformProps={platformProps}
							health={health}
							propose={propose}
							timelock={timelock}
							refresh={refresh}
							lastUpdated={lastUpdated}
							rosterOnChain={rosterOnChain}
							loading={loading}
						/>
					</>
				)}

				<ProposalDialog
					timelock={timelock}
					request={proposal}
					onClose={() => setProposal(undefined)}
				/>
				<SessionWarning
					wallet={wallet}
					connect={connect}
					chainId={deployment.chainId}
				/>
			</Container>
		</Box>
	);
}

/**
 * The page for the current route. The panels are mounted as they were under the old tab bars; the
 * later layers of this redesign replace them one tab at a time.
 */
function RouteView({
	route,
	platformProps,
	health,
	propose,
	timelock,
	refresh,
	lastUpdated,
	rosterOnChain,
	loading,
}: {
	route: Route;
	platformProps: PlatformAreaProps;
	health: HealthReport | undefined;
	propose: Propose | undefined;
	timelock: GianoTimelockClient | undefined;
	refresh: () => Promise<void>;
	lastUpdated: Date | undefined;
	rosterOnChain: boolean;
	loading: boolean;
}) {
	const { platformApi } = getAdminConfig();
	const { client, overview, myRoles, wallet, deployment } = platformProps;

	if (route.tab === "not-found" || (route.tab === "admins" && !platformApi))
		return <NotFound />;
	if (route.tab === "admins") return <AdminsTab />;

	if (!overview || !client)
		return loading ? (
			<Stack align="center" py="16" gap="3">
				<Spinner size="lg" color="brand.solid" />
				<Text color="fg.muted">Reading the paymaster…</Text>
			</Stack>
		) : null;

	switch (route.tab) {
		case "overview":
			return <OverviewPanel overview={overview} />;
		case "tenants":
			return (
				<Stack gap="6">
					{platformApi && (
						<TenantsTab
							{...platformProps}
							selected={route.tenant}
							lastUpdated={lastUpdated}
						/>
					)}
					<TenantsPanel
						client={client}
						tenants={overview.tenants}
						myRoles={myRoles}
						connected={wallet !== undefined}
						rosterOnChain={rosterOnChain}
						refresh={refresh}
						propose={propose}
					/>
				</Stack>
			);
		case "paymaster":
			return (
				<SettingsPanel
					client={client}
					overview={overview}
					myRoles={myRoles}
					refresh={refresh}
					propose={propose}
				/>
			);
		case "roles":
			return (
				<RolesPanel
					client={client}
					roles={overview.roles}
					myRoles={myRoles}
					account={wallet?.address}
					refresh={refresh}
					propose={propose}
					timelockAddress={deployment.timelockAddress}
				/>
			);
		case "timelock":
			return (
				<TimelockPanel
					timelock={timelock}
					tenants={overview.tenants}
					connected={wallet !== undefined}
					propose={propose}
					refresh={refresh}
					lastUpdated={lastUpdated}
				/>
			);
		case "activity":
			return <HistoryPanel client={client} />;
		case "health":
			return health ? <HealthPanel health={health} /> : null;
	}
}

function NotFound() {
	return (
		<Stack align="center" py="16" gap="3">
			<Heading size="md">No such page</Heading>
			<Text color="fg.muted">
				The console has no page at {window.location.pathname}.
			</Text>
			<Link to={TAB_PATHS.overview} color="brand.fg" fontWeight="medium">
				Go to the Overview
			</Link>
		</Stack>
	);
}
