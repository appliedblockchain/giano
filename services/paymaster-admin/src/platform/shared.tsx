import type {
	PaymasterOverview,
	PaymasterRoleName,
	TenantView,
} from "@appliedblockchain/giano-paymaster-sdk";
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
import { eth } from "../lib/format";
import type { ApiError, TenantStatus } from "../lib/platform-api";

/** Where a registry tenant stands on the selected chain's paymaster, matched on tenant id. */
export type OnChainState =
	| "enabled"
	| "disabled"
	| "not-registered"
	| "unknown";

/** The roster, keyed by the UUID form of the tenant id — the same id the registry row carries. */
export function rosterByUuid(
	overview: PaymasterOverview | undefined,
): Map<string, TenantView> | undefined {
	if (!overview) return undefined;
	return new Map(
		overview.tenants.map((tenant) => [tenant.uuid.toLowerCase(), tenant]),
	);
}

export function onChainState(
	roster: Map<string, TenantView> | undefined,
	tenantId: string,
): OnChainState {
	if (!roster) return "unknown";
	const entry = roster.get(tenantId.toLowerCase());
	if (!entry) return "not-registered";
	return entry.enabled ? "enabled" : "disabled";
}

const ON_CHAIN = {
	enabled: { colorPalette: "green", label: "registered · enabled" },
	disabled: { colorPalette: "orange", label: "registered · disabled" },
	"not-registered": { colorPalette: "gray", label: "not registered" },
	unknown: { colorPalette: "gray", label: "paymaster not read" },
} as const;

export function OnChainBadge({ state }: { state: OnChainState }) {
	const tone = ON_CHAIN[state];
	return (
		<Badge
			colorPalette={tone.colorPalette}
			variant={state === "enabled" ? "subtle" : "outline"}
		>
			{tone.label}
		</Badge>
	);
}

const LIFECYCLE = {
	active: "green",
	suspended: "orange",
	deleted: "red",
} as const;

export function LifecycleBadge({ status }: { status: TenantStatus }) {
	return (
		<Badge
			colorPalette={LIFECYCLE[status]}
			variant={status === "active" ? "subtle" : "solid"}
		>
			{status}
		</Badge>
	);
}

/** Who wrote a history entry or issued a key: the platform admin's id, or any other writer as recorded. */
export const actorLabel = (actor: string) =>
	actor.startsWith("platform-admin:") ? actor.split(":")[1] : actor;

/** The tenant-admin role every on-chain follow-up needs, as the console already reads it. */
export const canAdministerOnChain = (myRoles: readonly PaymasterRoleName[]) =>
	myRoles.includes("TENANT_ADMIN_ROLE");

/**
 * A refused platform admin call, shown with what the API said and the detail it attached: the tenant
 * holding a contested origin, or each chain's figures for a delete blocked by funds.
 */
export function ApiErrorAlert({
	error,
	title,
}: {
	error: ApiError;
	title?: string;
}) {
	const chains = Array.isArray(error.chains)
		? (error.chains as {
				chainId: number;
				balanceWei?: string;
				deficitWei?: string;
				lastSyncedBlock?: string | null;
				headBlock?: string | null;
			}[])
		: [];
	return (
		<Alert.Root status="error" size="sm">
			<Alert.Indicator />
			<Alert.Content>
				<Alert.Title>
					{title ?? EXPLAIN[error.error] ?? error.error}
				</Alert.Title>
				<Alert.Description>
					<Stack gap="1">
						<Text>{error.message}</Text>
						{typeof error.slug === "string" &&
							typeof error.origin === "string" && (
								<Text>
									{error.origin} belongs to tenant <b>{error.slug}</b>.
								</Text>
							)}
						{chains.map((chain) => (
							<Text key={chain.chainId} fontFamily="mono" fontSize="xs">
								chain {chain.chainId}
								{chain.balanceWei !== undefined &&
									` · balance ${eth(BigInt(chain.balanceWei))}`}
								{chain.deficitWei !== undefined &&
									` · deficit ${eth(BigInt(chain.deficitWei))}`}
								{chain.headBlock !== undefined &&
									` · head ${chain.headBlock ?? "unreachable"}`}
								{chain.lastSyncedBlock !== undefined &&
									` · ledger at block ${chain.lastSyncedBlock ?? "never synced"}`}
							</Text>
						))}
					</Stack>
				</Alert.Description>
			</Alert.Content>
		</Alert.Root>
	);
}

/** What each API refusal means for a platform admin, in their terms. */
const EXPLAIN: Record<string, string> = {
	"origin-claimed": "That origin already belongs to another tenant",
	conflict: "Another tenant already uses that value",
	"invalid-transition": "Not possible in the tenant’s current state",
	"tenant-not-suspended": "Suspend the tenant before deleting it",
	"tenant-has-funds": "The tenant still has a balance or deficit on-chain",
	"tenant-has-reservations":
		"The tenant has sponsorship reservations still open",
	"ledger-stale": "The paymaster ledger is too far behind to trust",
	"last-admin-key":
		"This is the last admin key of a tenant with closed registration",
	"last-admin": "The last platform admin cannot be removed",
	"self-removal": "You cannot remove yourself — ask another platform admin",
	"version-mismatch": "Someone else changed this tenant",
	validation: "Some fields need attention",
};

/** The issues of a 400, keyed by the top-level field their JSON-pointer path names. */
export function issuesByField(
	error: ApiError | undefined,
): Record<string, string[]> {
	const byField: Record<string, string[]> = {};
	for (const issue of error?.issues ?? []) {
		const field = issue.path.split("/").filter(Boolean)[0] ?? "(form)";
		byField[field] = [...(byField[field] ?? []), issue.message];
	}
	return byField;
}

export const linesToList = (text: string) =>
	text
		.split(/[\n,]/)
		.map((line) => line.trim())
		.filter(Boolean);

/**
 * An on-chain follow-up to a platform admin action that already succeeded: offered, never required, and
 * never a reason to undo the API action. Disabled, with the reason, without TENANT_ADMIN_ROLE.
 */
export function OnChainStep({
	title,
	description,
	allowed,
	busy,
	actionLabel,
	onAct,
	children,
}: {
	title: string;
	description: ReactNode;
	allowed: boolean;
	busy: boolean;
	actionLabel: string;
	onAct: () => void;
	children?: ReactNode;
}) {
	return (
		<Box borderWidth="1px" rounded="md" p="3" bg="bg.subtle">
			<Stack gap="2">
				<Text fontWeight="medium">{title}</Text>
				<Text fontSize="sm" color="fg.muted">
					{description}
				</Text>
				{children}
				<HStack>
					<Button
						size="sm"
						colorPalette="brand"
						onClick={onAct}
						loading={busy}
						disabled={!allowed}
					>
						{actionLabel}
					</Button>
					{!allowed && (
						<Text fontSize="xs" color="fg.muted">
							Needs TENANT_ADMIN_ROLE on this paymaster, which the connected
							wallet does not hold.
						</Text>
					)}
				</HStack>
			</Stack>
		</Box>
	);
}
