import type { HealthLevel } from "@appliedblockchain/giano-paymaster-sdk";
import { Badge, HStack } from "@chakra-ui/react";
import type { ComponentType } from "react";
import {
	LuHeartPulse,
	LuHistory,
	LuHourglass,
	LuLayoutDashboard,
	LuShieldCheck,
	LuSlidersHorizontal,
	LuUserCog,
	LuUsers,
} from "react-icons/lu";
import { Link, type Route, TAB_PATHS, type Tab } from "../lib/router";

const TABS: { tab: Tab; label: string; icon: ComponentType }[] = [
	{ tab: "overview", label: "Overview", icon: LuLayoutDashboard },
	{ tab: "tenants", label: "Tenants", icon: LuUsers },
	{ tab: "paymaster", label: "Paymaster", icon: LuSlidersHorizontal },
	{ tab: "roles", label: "Roles", icon: LuShieldCheck },
	{ tab: "timelock", label: "Timelock", icon: LuHourglass },
	{ tab: "activity", label: "Activity", icon: LuHistory },
	{ tab: "health", label: "Health", icon: LuHeartPulse },
	{ tab: "admins", label: "Admins", icon: LuUserCog },
];

/**
 * One tab bar for the whole console (openspec redesign-paymaster-console, D2): the Paymaster and
 * Platform areas it replaces split one tenant across two places. Links, not ARIA tabs — each one is
 * a page with its own URL, and `aria-current` is what says which page this is.
 */
export function TabBar({
	route,
	platformApi,
	tenants,
	healthLevel,
}: {
	route: Route;
	platformApi: boolean;
	tenants: number | undefined;
	healthLevel: HealthLevel | undefined;
}) {
	const tabs = TABS.filter(({ tab }) => tab !== "admins" || platformApi);
	return (
		<HStack
			as="nav"
			aria-label="Console"
			gap="1"
			borderBottomWidth="1px"
			mb="6"
			overflowX="auto"
		>
			{tabs.map(({ tab, label, icon: Icon }) => {
				const current = route.tab === tab;
				return (
					<Link
						key={tab}
						to={TAB_PATHS[tab]}
						aria-current={current ? "page" : undefined}
						display="flex"
						alignItems="center"
						gap="2"
						px="3"
						py="2.5"
						mb="-1px"
						fontSize="sm"
						fontWeight="medium"
						whiteSpace="nowrap"
						color={current ? "fg" : "fg.muted"}
						borderBottomWidth="2px"
						borderColor={current ? "brand.solid" : "transparent"}
						_hover={{ color: "fg", textDecoration: "none" }}
						focusRing="inside"
					>
						<Icon />
						{label}
						{tab === "tenants" && tenants !== undefined && ` (${tenants})`}
						{tab === "health" && healthLevel && healthLevel !== "ok" && (
							<Badge
								colorPalette={healthLevel === "fail" ? "red" : "orange"}
								variant="solid"
								size="sm"
								aria-label={healthLevel === "fail" ? "failing" : "warning"}
							>
								!
							</Badge>
						)}
					</Link>
				);
			})}
		</HStack>
	);
}
