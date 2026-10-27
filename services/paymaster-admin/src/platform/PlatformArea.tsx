import type {
	GianoPaymasterClient,
	PaymasterOverview,
	PaymasterRoleName,
} from "@appliedblockchain/giano-paymaster-sdk";
import { Badge, Button, HStack, Tabs, Text } from "@chakra-ui/react";
import { LuLogOut, LuShieldCheck, LuUsers } from "react-icons/lu";
import { Copyable } from "../components/ui";
import type { Deployment } from "../config";
import type { ConnectedWallet } from "../lib/chain";
import { usePlatform } from "../lib/platform-session";
import { AdminsTab } from "./AdminsTab";
import { SignIn } from "./SignIn";
import { TenantsTab } from "./TenantsTab";

export type PlatformAreaProps = {
	deployment: Deployment;
	wallet: ConnectedWallet | undefined;
	connect: () => Promise<ConnectedWallet | undefined>;
	connecting: boolean;
	/** The chain side: the paymaster roster the registry is joined to, and the roles that gate on-chain steps. */
	client: GianoPaymasterClient | undefined;
	overview: PaymasterOverview | undefined;
	myRoles: readonly PaymasterRoleName[];
	refreshChain: () => Promise<void>;
};

/**
 * The Platform area (specs/PLATFORM-ADMIN-SPECS.md §11.2): Giano's own staff administering the
 * tenant registry in wallet-api, and the list of platform admins itself. Shown only where the console has a platform admin API to reach.
 * Without a session it is the sign-in view and nothing else — as is the Paymaster area there.
 */
export function PlatformArea(props: PlatformAreaProps) {
	const { session } = usePlatform();
	if (!session) return <SignIn {...props} />;

	return (
		<Tabs.Root defaultValue="tenants" lazyMount>
			<Tabs.List mb="4">
				<Tabs.Trigger value="tenants">
					<LuUsers /> Tenants
				</Tabs.Trigger>
				<Tabs.Trigger value="admins">
					<LuShieldCheck /> Admins
				</Tabs.Trigger>
			</Tabs.List>
			<Tabs.Content value="tenants">
				<TenantsTab {...props} />
			</Tabs.Content>
			<Tabs.Content value="admins">
				<AdminsTab />
			</Tabs.Content>
		</Tabs.Root>
	);
}

/**
 * Who is signed in, until when, and the way out. Above both areas: where the platform API is
 * configured, one session is what the whole console reads with, not just the Platform area.
 */
export function SessionBar() {
	const { session, signOut } = usePlatform();
	if (!session) return null;
	return (
		<HStack
			justify="space-between"
			flexWrap="wrap"
			gap="3"
			borderWidth="1px"
			rounded="lg"
			px="4"
			py="2"
			mb="4"
			bg="surface"
		>
			<HStack gap="3" flexWrap="wrap">
				<Badge colorPalette="brand" variant="solid">
					admin
				</Badge>
				<Text fontWeight="medium">{session.admin.id}</Text>
				<Copyable
					value={session.admin.address}
					label="Platform admin address"
				/>
				<Text fontSize="xs" color="fg.muted">
					session until {session.expiresAt.toLocaleTimeString()}
				</Text>
			</HStack>
			<Button size="sm" variant="ghost" onClick={() => void signOut()}>
				<LuLogOut /> Sign out
			</Button>
		</HStack>
	);
}
