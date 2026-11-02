import type {
	GianoPaymasterClient,
	TenantView,
} from "@appliedblockchain/giano-paymaster-sdk";
import {
	Alert,
	Box,
	DataList,
	Field,
	HStack,
	Input,
	Separator,
	SimpleGrid,
	Stack,
	Text,
} from "@chakra-ui/react";
import { type ReactNode, useState } from "react";
import { ActionButton } from "../components/actions";
import {
	AddressInput,
	AmountInput,
	useAddressInput,
	useAmountInput,
} from "../components/inputs";
import { QueuedMarker } from "../components/status";
import { SectionCard } from "../components/ui";
import { AddressLabel, Amount } from "../components/values";
import type { TenantDetail } from "../lib/platform-api";
import { queuedKeys } from "../lib/queued";
import { compareLedger, type OnChainState } from "../lib/tenants";
import { OnChainBadge } from "../platform/shared";
import { useConsole } from "../shell/ConsoleContext";

/**
 * A tenant on the selected chain's paymaster (openspec platform-console-tenants): its record, the
 * writes that apply to it — each Send, Propose or disabled by the console's write rules — and
 * whether wallet-api's ledger agrees with what the chain says.
 */
export function OnChainCard({
	client,
	tenantId,
	slug,
	onChain,
	state,
	ledger,
}: {
	/** Undefined while the paymaster has not been read, when `state` is "unknown" too. */
	client: GianoPaymasterClient | undefined;
	/** The UUID, as the registry and the paymaster share it. */
	tenantId: string;
	/** The registry slug, emitted at registration; undefined for a tenant with no registry row. */
	slug: string | undefined;
	onChain: TenantView | undefined;
	state: OnChainState;
	/** wallet-api's ledger rows, with the platform API. */
	ledger: TenantDetail["ledger"] | undefined;
}) {
	const { deployment, block } = useConsole();
	return (
		<SectionCard
			title={`On ${deployment.name}`}
			subtitle={`The paymaster on chain ${deployment.chainId}${block !== undefined ? `, read at block ${block}` : ""}.`}
			action={<OnChainBadge state={state} />}
		>
			{state === "unknown" || !client ? (
				<Text color="fg.muted">The paymaster has not been read yet.</Text>
			) : onChain ? (
				<Registered client={client} tenant={onChain} ledger={ledger} />
			) : (
				<Register client={client} tenantId={tenantId} slug={slug} />
			)}
		</SectionCard>
	);
}

function Register({
	client,
	tenantId,
	slug,
}: {
	client: GianoPaymasterClient;
	tenantId: string;
	slug: string | undefined;
}) {
	const { deployment } = useConsole();
	const withdrawTo = useAddressInput();
	const address = withdrawTo.value;
	return (
		<Stack gap="3">
			<Text fontSize="sm">
				Not registered on this paymaster, so it cannot be funded or sponsored
				here. Registration is once-only: the roster only grows.
			</Text>
			<AddressInput
				input={withdrawTo}
				label="Withdrawal address"
				helper="The only address that will ever be able to withdraw this tenant's balance."
			/>
			<ActionButton
				target={{ role: "TENANT_ADMIN_ROLE" }}
				label={`Register on ${deployment.name}`}
				send={
					address && slug
						? () => client.registerTenant(tenantId, address, slug)
						: undefined
				}
				onDone={withdrawTo.clear}
			/>
		</Stack>
	);
}

function Registered({
	client,
	tenant,
	ledger,
}: {
	client: GianoPaymasterClient;
	tenant: TenantView;
	ledger: TenantDetail["ledger"] | undefined;
}) {
	const { deployment } = useConsole();
	const fund = useAmountInput();
	// 0 is a fee: free sponsorship for this tenant, which is not the same as clearing the override.
	const fee = useAmountInput(undefined, undefined, { allowZero: true });
	const withdrawTo = useAddressInput();
	const amount = fund.value;
	const feeWei = fee.value;
	const address = withdrawTo.value;

	return (
		<Stack gap="4">
			<DataList.Root orientation="horizontal" size="sm">
				<Item label="Balance">
					<Amount wei={tenant.balance} />
				</Item>
				<Item label="Deficit">
					<Box color={tenant.deficit > 0n ? "red.fg" : undefined}>
						<Amount wei={tenant.deficit} />
					</Box>
				</Item>
				<Item label="Fee">
					<Stack gap="1">
						<HStack gap="2">
							<Amount wei={tenant.effectiveFeeWei} decimals={6} />
							<Text fontSize="xs" color="fg.muted">
								{tenant.hasFeeOverride ? "override" : "the default"}
							</Text>
						</HStack>
						<QueuedMarker keys={queuedKeys.tenantFee(tenant.id)} />
					</Stack>
				</Item>
				<Item label="Withdraws to">
					<Stack gap="1">
						<AddressLabel
							address={tenant.withdrawAddress}
							label="Withdrawal address"
						/>
						<QueuedMarker keys={queuedKeys.tenantWithdraw(tenant.id)} />
					</Stack>
				</Item>
			</DataList.Root>

			{ledger && (
				<LedgerAgreement
					tenant={tenant}
					row={ledger.find((entry) => entry.chainId === deployment.chainId)}
				/>
			)}

			<Separator />

			<SimpleGrid columns={{ base: 1, md: 2 }} gap="5">
				<Stack gap="2">
					<AmountInput
						input={fund}
						label="Fund"
						helper="Anyone may fund a tenant."
					/>
					{tenant.deficit > 0n && (
						<Text fontSize="xs" color="orange.fg">
							Funding clears the deficit first and credits only the remainder.
						</Text>
					)}
					<ActionButton
						target={{ anyone: true }}
						label="Fund"
						send={
							amount ? () => client.depositFor(tenant.id, amount) : undefined
						}
						onDone={fund.clear}
					/>
				</Stack>

				<Stack gap="2">
					<Text fontSize="sm" fontWeight="medium">
						Sponsorship
					</Text>
					<Text fontSize="xs" color="fg.muted">
						{tenant.enabled
							? "Enabled: its operations are sponsored while it has a balance."
							: "Disabled: nothing is sponsored for it until it is enabled."}
					</Text>
					<ActionButton
						target={{ role: "TENANT_ADMIN_ROLE" }}
						label={tenant.enabled ? "Disable" : "Enable"}
						destructive={tenant.enabled}
						send={() => client.setTenantEnabled(tenant.id, !tenant.enabled)}
						confirm={
							tenant.enabled
								? {
										title: "Disable sponsorship",
										effect:
											"Nothing more is sponsored for this tenant on this chain until it is enabled again. Its balance stays where it is.",
										confirmLabel: "Disable",
									}
								: undefined
						}
					/>
				</Stack>

				<Stack gap="2">
					<AmountInput
						input={fee}
						label="Fee override"
						helper="Charged per sponsored operation instead of the default."
					/>
					<ActionButton
						target={{ operation: "setTenantFee" }}
						label="Set fee override"
						send={
							feeWei !== undefined
								? () => client.setTenantFee(tenant.id, true, feeWei)
								: undefined
						}
						proposal={
							feeWei !== undefined
								? {
										kind: "setTenantFee",
										tenantId: tenant.id,
										hasOverride: true,
										feeWei,
									}
								: undefined
						}
						onDone={fee.clear}
					/>
					{tenant.hasFeeOverride && (
						<ActionButton
							target={{ operation: "setTenantFee" }}
							label="Clear the fee override"
							send={() => client.setTenantFee(tenant.id, false, 0n)}
							proposal={{
								kind: "setTenantFee",
								tenantId: tenant.id,
								hasOverride: false,
								feeWei: 0n,
							}}
						/>
					)}
				</Stack>

				<Stack gap="2">
					<AddressInput
						input={withdrawTo}
						label="New withdrawal address"
						helper="Where this tenant's balance can be withdrawn to."
					/>
					<ActionButton
						target={{ operation: "setTenantWithdrawAddress" }}
						label="Change withdrawal address"
						send={
							address
								? () => client.setTenantWithdrawAddress(tenant.id, address)
								: undefined
						}
						proposal={
							address
								? {
										kind: "setTenantWithdrawAddress",
										tenantId: tenant.id,
										withdrawAddress: address,
									}
								: undefined
						}
						onDone={withdrawTo.clear}
					/>
				</Stack>
			</SimpleGrid>

			<Text fontSize="xs" color="fg.muted">
				Withdrawing a tenant's balance is not offered here: only its withdrawal
				address can do that, and no role on the paymaster can reach those funds.
			</Text>
		</Stack>
	);
}

/** wallet-api's ledger against the chain, approximately: at the block the console read (openspec D10). */
function LedgerAgreement({
	tenant,
	row,
}: {
	tenant: TenantView;
	row: TenantDetail["ledger"][number] | undefined;
}) {
	const { block } = useConsole();
	const comparison = compareLedger(row, tenant, block);
	if (comparison.kind === "agrees")
		return (
			<Text fontSize="sm" color="fg.muted" data-testid="ledger-agreement">
				wallet-api's ledger agrees with the chain
				{row?.lastSyncedBlock
					? ` (synced to block ${row.lastSyncedBlock})`
					: ""}
				.
			</Text>
		);
	if (comparison.kind === "no-ledger")
		return (
			<Text fontSize="sm" color="orange.fg" data-testid="ledger-agreement">
				wallet-api has no ledger row for this tenant on this chain yet.
			</Text>
		);
	return (
		<Alert.Root status="warning" size="sm" data-testid="ledger-agreement">
			<Alert.Indicator />
			<Alert.Content>
				<Alert.Title>wallet-api's ledger differs from the chain</Alert.Title>
				<Alert.Description>
					<Stack gap="1">
						<Text>
							Ledger: balance <Amount wei={comparison.ledgerBalance} />, deficit{" "}
							<Amount wei={comparison.ledgerDeficit} />. Chain:{" "}
							<Amount wei={tenant.balance} />, deficit{" "}
							<Amount wei={tenant.deficit} />.
						</Text>
						<Text>
							{comparison.lag === undefined
								? "The ledger has never synced."
								: comparison.lag > 0n
									? `The ledger is ${comparison.lag} blocks behind; it should catch up.`
									: "The ledger is synced to the block read, so this is drift, not lag."}
						</Text>
					</Stack>
				</Alert.Description>
			</Alert.Content>
		</Alert.Root>
	);
}

function Item({ label, children }: { label: string; children: ReactNode }) {
	return (
		<DataList.Item>
			<DataList.ItemLabel minW="28">{label}</DataList.ItemLabel>
			<DataList.ItemValue>{children}</DataList.ItemValue>
		</DataList.Item>
	);
}

/** Register a tenant by id, for a console with no platform API and so no registry to start from. */
export function RegisterById({ client }: { client: GianoPaymasterClient }) {
	const { deployment } = useConsole();
	const [tenantId, setTenantId] = useState("");
	const [slug, setSlug] = useState("");
	const withdrawTo = useAddressInput();
	const address = withdrawTo.value;
	const id = tenantId.trim();
	const validId =
		/^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$/i.test(
			id,
		) || /^0x[0-9a-f]{32}$/i.test(id);
	return (
		<Stack gap="3">
			<Field.Root invalid={id !== "" && !validId}>
				<Field.Label fontSize="sm">Tenant id</Field.Label>
				<Input
					size="sm"
					fontFamily="mono"
					value={tenantId}
					onChange={(event) => setTenantId(event.target.value)}
					placeholder="UUID, or a 16-byte hex id"
				/>
				<Field.ErrorText>A UUID, or 0x and 32 hex characters.</Field.ErrorText>
				<Field.HelperText>
					The backend's tenant UUID, so there is no second identifier to keep in
					step.
				</Field.HelperText>
			</Field.Root>
			<Field.Root>
				<Field.Label fontSize="sm">Slug</Field.Label>
				<Input
					size="sm"
					value={slug}
					onChange={(event) => setSlug(event.target.value)}
					placeholder="acme"
				/>
				<Field.HelperText>
					Emitted for reconciliation against the backend, not stored on-chain.
				</Field.HelperText>
			</Field.Root>
			<AddressInput
				input={withdrawTo}
				label="Withdrawal address"
				helper="The only address that will ever be able to withdraw this tenant's balance."
			/>
			<ActionButton
				target={{ role: "TENANT_ADMIN_ROLE" }}
				label={`Register on ${deployment.name}`}
				send={
					address && validId && slug.trim()
						? () => client.registerTenant(id, address, slug.trim())
						: undefined
				}
				onDone={() => {
					setTenantId("");
					setSlug("");
					withdrawTo.clear();
				}}
			/>
		</Stack>
	);
}
