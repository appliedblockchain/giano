import {
	PAYMASTER_ROLE_NAMES,
	type PaymasterRoleName,
	type TenantView,
} from "@appliedblockchain/giano-paymaster-sdk";
import {
	Button,
	Field,
	HStack,
	NativeSelect,
	Stack,
	Text,
} from "@chakra-ui/react";
import { useState } from "react";
import { LuPlus } from "react-icons/lu";
import type { ProposalRequest } from "../lib/proposals";
import {
	AddressInput,
	AmountInput,
	CalldataInput,
	useAddressInput,
	useAmountInput,
	useCalldataInput,
} from "./inputs";

type Kind =
	| "setDefaultFee"
	| "setTenantFee"
	| "clearTenantFee"
	| "setTenantWithdrawAddress"
	| "grantRole"
	| "revokeRole"
	| "upgradeToAndCall";

const KINDS: { kind: Kind; label: string }[] = [
	{ kind: "setDefaultFee", label: "Set the default fee" },
	{ kind: "setTenantFee", label: "Set a tenant's fee override" },
	{ kind: "clearTenantFee", label: "Clear a tenant's fee override" },
	{ kind: "setTenantWithdrawAddress", label: "Change a withdrawal address" },
	{ kind: "grantRole", label: "Grant a paymaster role" },
	{ kind: "revokeRole", label: "Revoke a paymaster role" },
	{ kind: "upgradeToAndCall", label: "Upgrade the paymaster" },
];

/**
 * One timelocked paymaster call, chosen and filled in, handed to `onAdd` as a request. Building it
 * needs no role and no wallet; each field validates as it is typed and the button waits for all of
 * them. The timelock's own delays and roles have their own controls in the Timelock tab.
 */
export function CallForm({
	tenants,
	onAdd,
	actionLabel,
}: {
	tenants: readonly TenantView[];
	onAdd: (request: ProposalRequest) => void;
	actionLabel: string;
}) {
	const [kind, setKind] = useState<Kind>("setDefaultFee");
	// The first tenant until one is chosen, following the list: tenants read after the form opened
	// are offered too, rather than leaving it on none.
	const [chosenTenant, setTenant] = useState<string>("");
	const tenant = chosenTenant || tenants[0]?.id || "";
	const [role, setRole] = useState<PaymasterRoleName>("FEE_ADMIN_ROLE");
	// 0 is a fee: free sponsorship, for every tenant or for one.
	const fee = useAmountInput(undefined, undefined, { allowZero: true });
	const address = useAddressInput();
	const data = useCalldataInput();

	const tenantId = tenants.find((entry) => entry.id === tenant)?.id;
	const needsTenant =
		kind === "setTenantFee" ||
		kind === "clearTenantFee" ||
		kind === "setTenantWithdrawAddress";
	const needsFee = kind === "setDefaultFee" || kind === "setTenantFee";
	const needsAddress =
		kind === "setTenantWithdrawAddress" ||
		kind === "grantRole" ||
		kind === "revokeRole" ||
		kind === "upgradeToAndCall";
	const needsRole = kind === "grantRole" || kind === "revokeRole";

	const request = ((): ProposalRequest | undefined => {
		const account = address.value;
		const feeWei = fee.value;
		switch (kind) {
			case "setDefaultFee":
				return feeWei !== undefined ? { kind, feeWei } : undefined;
			case "setTenantFee":
				return feeWei !== undefined && tenantId
					? { kind, tenantId, hasOverride: true, feeWei }
					: undefined;
			case "clearTenantFee":
				return tenantId
					? { kind: "setTenantFee", tenantId, hasOverride: false, feeWei: 0n }
					: undefined;
			case "setTenantWithdrawAddress":
				return account && tenantId
					? { kind, tenantId, withdrawAddress: account }
					: undefined;
			case "grantRole":
			case "revokeRole":
				return account ? { kind, role, account } : undefined;
			case "upgradeToAndCall":
				return account && !data.error
					? { kind, implementation: account, data: data.value ?? "0x" }
					: undefined;
		}
	})();

	return (
		<Stack gap="3">
			<HStack gap="3" flexWrap="wrap" align="flex-start">
				<Field.Root width="auto" minW="16rem">
					<Field.Label fontSize="sm">Change</Field.Label>
					<NativeSelect.Root size="sm">
						<NativeSelect.Field
							value={kind}
							onChange={(event) => setKind(event.currentTarget.value as Kind)}
						>
							{KINDS.map((entry) => (
								<option key={entry.kind} value={entry.kind}>
									{entry.label}
								</option>
							))}
						</NativeSelect.Field>
						<NativeSelect.Indicator />
					</NativeSelect.Root>
				</Field.Root>
				{needsTenant && (
					<Field.Root width="auto" minW="22rem">
						<Field.Label fontSize="sm">Tenant</Field.Label>
						<NativeSelect.Root size="sm">
							<NativeSelect.Field
								value={tenant}
								onChange={(event) => setTenant(event.currentTarget.value)}
								fontFamily="mono"
							>
								{tenants.map((entry) => (
									<option key={entry.id} value={entry.id}>
										{entry.uuid}
									</option>
								))}
							</NativeSelect.Field>
							<NativeSelect.Indicator />
						</NativeSelect.Root>
					</Field.Root>
				)}
				{needsRole && (
					<Field.Root width="auto" minW="16rem">
						<Field.Label fontSize="sm">Role</Field.Label>
						<NativeSelect.Root size="sm">
							<NativeSelect.Field
								value={role}
								onChange={(event) =>
									setRole(event.currentTarget.value as PaymasterRoleName)
								}
							>
								{PAYMASTER_ROLE_NAMES.map((name) => (
									<option key={name} value={name}>
										{name}
									</option>
								))}
							</NativeSelect.Field>
							<NativeSelect.Indicator />
						</NativeSelect.Root>
					</Field.Root>
				)}
			</HStack>
			{needsFee && <AmountInput input={fee} label="Fee" />}
			{needsAddress && (
				<AddressInput
					input={address}
					label={
						kind === "setTenantWithdrawAddress"
							? "New withdrawal address"
							: kind === "upgradeToAndCall"
								? "New implementation"
								: "Account"
					}
				/>
			)}
			{kind === "upgradeToAndCall" && (
				<CalldataInput input={data} label="Call after upgrading (optional)" />
			)}
			{needsTenant && tenants.length === 0 && (
				<Text fontSize="sm" color="fg.muted">
					No tenants are registered on this paymaster.
				</Text>
			)}
			<HStack>
				<Button
					size="sm"
					variant="outline"
					colorPalette="timelock"
					disabled={!request}
					onClick={() => request && onAdd(request)}
				>
					<LuPlus /> {actionLabel}
				</Button>
			</HStack>
		</Stack>
	);
}
