import {
	type AdminEvent,
	formatDuration,
} from "@appliedblockchain/giano-paymaster-sdk";

/** What the Activity tab's filter offers, in the order an operator looks for them. */
export type EventGroup =
	| "roles"
	| "fees"
	| "signers"
	| "state"
	| "tenants"
	| "funds"
	| "timelock";

export const EVENT_GROUPS: { group: EventGroup; label: string }[] = [
	{ group: "roles", label: "Roles" },
	{ group: "fees", label: "Fees and parameters" },
	{ group: "signers", label: "Signing keys" },
	{ group: "state", label: "Pause and upgrades" },
	{ group: "tenants", label: "Tenants" },
	{ group: "funds", label: "Funds" },
	{ group: "timelock", label: "Timelock" },
];

export function eventGroup(event: AdminEvent): EventGroup {
	if (event.source === "timelock") return "timelock";
	// The paymaster's stake, from the EntryPoint.
	if (event.source === "entrypoint") return "funds";
	switch (event.kind) {
		case "RoleGranted":
		case "RoleRevoked":
		case "RoleAdminChanged":
			return "roles";
		case "FeeChanged":
		case "TenantFeeChanged":
		case "ParamChanged":
			return "fees";
		case "SignerAdded":
		case "SignerRemoved":
			return "signers";
		case "Paused":
		case "Unpaused":
		case "Upgraded":
			return "state";
		case "TenantFunded":
		case "TenantWithdrawn":
		case "FeesWithdrawn":
			return "funds";
		default:
			return "tenants";
	}
}

/** How a sentence names what it mentions: the console's names for addresses, slugs for tenants. */
export type Namer = {
	address: (address: string) => string;
	tenant: (uuid: string) => string;
	money: (wei: bigint) => string;
	/** A unix time, for a stake's unlock. */
	time: (unix: number) => string;
};

/**
 * What an event did, as a sentence without its subject: the Activity list puts who did it beside
 * it. Every admin event kind has its own; a new kind reads as its name until it gets one.
 */
export function describeAdminEvent(event: AdminEvent, name: Namer): string {
	const arg = (key: string) => event.args[key];
	const address = (key: string) => name.address(String(arg(key)));
	const tenant = event.tenant ? name.tenant(event.tenant.uuid) : "a tenant";
	const on = event.source === "timelock" ? " on the timelock" : "";
	switch (event.kind) {
		case "RoleGranted":
			// OpenZeppelin's timelock convention: EXECUTOR_ROLE held by address(0) is open to anyone.
			// Nothing else reads address(0) that way.
			return event.source === "timelock" &&
				arg("role") === "EXECUTOR_ROLE" &&
				BigInt(String(arg("account"))) === 0n
				? `opened ${arg("role")}${on} to anyone`
				: `granted ${arg("role")}${on} to ${address("account")}`;
		case "RoleRevoked":
			return String(arg("account")).toLowerCase() ===
				String(arg("sender")).toLowerCase()
				? `renounced ${arg("role")}${on}`
				: `revoked ${arg("role")}${on} from ${address("account")}`;
		case "RoleAdminChanged":
			return `made ${arg("newAdminRole")} the admin of ${arg("role")}${on}`;
		case "FeeChanged":
			return `changed the default fee from ${name.money(arg("oldFeeWei") as bigint)} to ${name.money(arg("newFeeWei") as bigint)}`;
		case "TenantFeeChanged":
			return arg("hasOverride")
				? `set ${tenant}'s fee to ${name.money(arg("feeWei") as bigint)}`
				: `removed ${tenant}'s fee override`;
		case "ParamChanged":
			return `changed ${arg("name")} from ${arg("oldValue")} to ${arg("newValue")}`;
		case "Paused":
			return "paused new sponsorships";
		case "Unpaused":
			return "unpaused sponsorships";
		case "SignerAdded":
			return `added the signing key ${address("signer")}`;
		case "SignerRemoved":
			return `removed the signing key ${address("signer")}`;
		case "Upgraded":
			return `upgraded the paymaster to ${address("implementation")}`;
		case "TenantRegistered":
			return `registered ${tenant}, withdrawing to ${address("withdrawAddress")}`;
		case "TenantEnabledChanged":
			return arg("enabled") ? `enabled ${tenant}` : `disabled ${tenant}`;
		case "TenantFunded": {
			const cleared = arg("deficitCleared") as bigint;
			return `funded ${tenant} with ${name.money(arg("amount") as bigint)}${cleared > 0n ? `, clearing a ${name.money(cleared)} deficit` : ""}`;
		}
		case "TenantWithdrawn":
			return `withdrew ${name.money(arg("amount") as bigint)} from ${tenant} to ${address("to")}`;
		case "TenantWithdrawAddressChanged":
			return `changed ${tenant}'s withdrawal address from ${address("oldAddress")} to ${address("newAddress")}`;
		case "FeesWithdrawn":
			return `withdrew ${name.money(arg("amount") as bigint)} of platform fees to ${address("to")}`;
		case "CallScheduled":
			return `scheduled: ${call(event, name)}, to wait ${formatDuration(arg("delay") as bigint)}`;
		case "CallExecuted":
			return `executed: ${call(event, name)}`;
		case "Cancelled":
			return `cancelled operation ${String(arg("id")).slice(0, 10)}…`;
		case "MinDelayChange":
			return `changed the minimum delay from ${formatDuration(arg("oldDuration") as bigint)} to ${formatDuration(arg("newDuration") as bigint)}`;
		case "FunctionDelayChange":
			// The SDK names the function only when the target is the paymaster.
			return `changed the delay of ${arg("functionName") ?? `${arg("selector")} on ${address("target")}`} from ${formatDuration(arg("oldDuration") as bigint)} to ${formatDuration(arg("newDuration") as bigint)}`;
		case "StakeLocked":
			return `locked ${name.money(arg("totalStaked") as bigint)} of stake, ${formatDuration(arg("unstakeDelaySec") as bigint)} to unlock`;
		case "StakeUnlocked":
			return `unlocked the stake, withdrawable from ${name.time(Number(arg("withdrawTime")))}`;
		case "StakeWithdrawn":
			return `withdrew ${name.money(arg("amount") as bigint)} of stake to ${address("withdrawAddress")}`;
		default:
			return event.kind;
	}
}

function call(event: AdminEvent, name: Namer): string {
	if (!event.call) return "a call";
	return (
		event.call.decoded?.summary ??
		`a call to ${name.address(event.call.target)}`
	);
}

/** An address in a sentence: its first known name with a short form, or the short form alone. */
export function shortAddress(
	address: string,
	names: readonly string[],
): string {
	const short = `${address.slice(0, 6)}…${address.slice(-4)}`;
	return names.length > 0 ? `${names[0]} (${short})` : short;
}
