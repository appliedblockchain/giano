import {
	formatDuration,
	type GianoPaymasterClient,
	PAYMASTER_ROLE_NAMES,
	type PaymasterRoleName,
	ROLE_DESCRIPTIONS,
	type RoleHolders,
} from "@appliedblockchain/giano-paymaster-sdk";
import {
	Alert,
	Badge,
	Box,
	Field,
	HStack,
	NativeSelect,
	SimpleGrid,
	Stack,
	Table,
	Text,
} from "@chakra-ui/react";
import { useState } from "react";
import { LuLogOut, LuUserMinus } from "react-icons/lu";
import { type Address, isAddressEqual } from "viem";
import { ActionButton } from "../components/actions";
import { AddressInput, useAddressInput } from "../components/inputs";
import {
	InlineError,
	QueuedMarker,
	StatusText,
	TimelockedTag,
} from "../components/status";
import { ExecuteButton } from "../components/timelock";
import { SectionCard } from "../components/ui";
import { AddressLabel } from "../components/values";
import {
	type TimelockAccess,
	useTimelockConfig,
} from "../hooks/useTimelockConfig";
import { queuedKeys } from "../lib/queued";
import { useConsole } from "../shell/ConsoleContext";

/**
 * Every paymaster role (openspec K3, G8): whether it is timelocked and for how long, who holds it —
 * named where the console knows the address — what it may and may not do, and any change queued
 * for it. Grants, revokes and renounces follow the write rules; a rotation is one operation.
 *
 * The "may not" half is the point rather than decoration: the security argument is a set of pairs
 * (the fee admin cannot collect the fees it sets; no role can reach a tenant balance), and whether a
 * grant is safe depends on seeing the pair.
 */
export function RolesTab({
	client,
	roles,
}: {
	client: GianoPaymasterClient;
	roles: readonly RoleHolders[];
}) {
	const access = useTimelockConfig();
	const named = roles.filter(
		(entry): entry is RoleHolders & { name: PaymasterRoleName } =>
			entry.name !== "DEFAULT_ADMIN_ROLE",
	);
	return (
		<Stack gap="4">
			<DefaultAdminCard
				client={client}
				holders={
					roles.find((entry) => entry.name === "DEFAULT_ADMIN_ROLE")?.holders ??
					[]
				}
			/>
			{access.error && (
				<InlineError
					title="Could not read the timelock's delays"
					error={access.error}
					retry={() => void access.reload()}
				/>
			)}
			<SectionCard
				title="Roles"
				subtitle="There is no owner and no superuser: every role is administered by ROLE_ADMIN. Timelocked roles belong to the timelock on a handed-off deployment, so their functions wait out a public delay; immediate roles stay on operational keys."
			>
				<Table.ScrollArea borderWidth="1px" rounded="md">
					<Table.Root size="sm">
						<Table.Header>
							<Table.Row>
								<Table.ColumnHeader>Role</Table.ColumnHeader>
								<Table.ColumnHeader>Holders</Table.ColumnHeader>
								<Table.ColumnHeader>May, and may not</Table.ColumnHeader>
							</Table.Row>
						</Table.Header>
						<Table.Body>
							{named.map((entry) => (
								<RoleRow
									key={entry.role}
									client={client}
									entry={entry}
									access={access}
								/>
							))}
						</Table.Body>
					</Table.Root>
				</Table.ScrollArea>
			</SectionCard>
			<ChangeCard client={client} roles={named} />
		</Stack>
	);
}

/** The delay a timelocked role's functions wait, from the timelock; a range when they differ. */
function roleDelay(
	access: TimelockAccess,
	role: PaymasterRoleName,
): string | undefined {
	const delays = access.config?.functions
		.filter((entry) => entry.role === role)
		.map((entry) => entry.effectiveDelay);
	if (!delays?.length) return undefined;
	const low = delays.reduce((a, b) => (a < b ? a : b));
	const high = delays.reduce((a, b) => (a > b ? a : b));
	return low === high
		? formatDuration(low)
		: `${formatDuration(low)}–${formatDuration(high)}`;
}

function RoleRow({
	client,
	entry,
	access,
}: {
	client: GianoPaymasterClient;
	entry: RoleHolders & { name: PaymasterRoleName };
	access: TimelockAccess;
}) {
	const { myRoles, deployment, wallet, timelockOperations } = useConsole();
	const description = ROLE_DESCRIPTIONS[entry.name];
	const delay = description.timelocked
		? roleDelay(access, entry.name)
		: undefined;
	const timelock = deployment.timelockAddress;
	const ready = timelockOperations.changes.filter(
		(change) =>
			change.key === queuedKeys.role(entry.name) && change.state === "ready",
	);

	return (
		<Table.Row data-testid={`role-${entry.name}`}>
			<Table.Cell verticalAlign="top">
				<Stack gap="1">
					<Text fontWeight="medium" fontSize="sm" fontFamily="mono">
						{entry.name}
					</Text>
					<HStack gap="1" flexWrap="wrap">
						{description.timelocked ? (
							<TimelockedTag>
								{delay ? `timelocked · ${delay}` : "timelocked"}
							</TimelockedTag>
						) : (
							<Badge variant="subtle" size="sm">
								immediate
							</Badge>
						)}
						{myRoles.includes(entry.name) && (
							<Badge colorPalette="brand" variant="subtle" size="sm">
								you hold it
							</Badge>
						)}
					</HStack>
					<QueuedMarker keys={queuedKeys.role(entry.name)} />
					{ready.map((change) => (
						<ExecuteButton
							key={change.operationId}
							operationId={change.operationId}
							mayExecute={access.mayExecute}
						/>
					))}
				</Stack>
			</Table.Cell>
			<Table.Cell verticalAlign="top">
				{entry.holders.length === 0 ? (
					<Text fontSize="sm" color="fg.muted">
						nobody
					</Text>
				) : (
					<Stack gap="3">
						{entry.holders.map((holder) => {
							const isYou =
								wallet !== undefined && isAddressEqual(holder, wallet.address);
							const outsideTimelock =
								description.timelocked &&
								timelock !== undefined &&
								!isAddressEqual(holder, timelock);
							return (
								<Stack
									key={holder}
									gap="1"
									data-testid={`holder-${holder.toLowerCase()}`}
								>
									<AddressLabel address={holder} label={entry.name} />
									{outsideTimelock && (
										<Badge
											colorPalette="orange"
											variant="outline"
											size="sm"
											alignSelf="flex-start"
										>
											timelocked role held outside the timelock
										</Badge>
									)}
									<HStack gap="2" flexWrap="wrap">
										<ActionButton
											target={{ operation: "revokeRole" }}
											label="Revoke"
											icon={<LuUserMinus />}
											size="xs"
											destructive
											send={() => client.revokeRole(entry.name, holder)}
											proposal={{
												kind: "revokeRole",
												role: entry.name,
												account: holder,
											}}
											confirm={{
												title: `Revoke ${entry.name}`,
												effect: isYou
													? `Your wallet will lose the ability to ${description.may}.`
													: `${holder} will no longer be able to ${description.may}.`,
												confirmLabel: "Revoke",
											}}
										/>
										{isYou && (
											<ActionButton
												target={{ role: entry.name }}
												label="Renounce"
												icon={<LuLogOut />}
												size="xs"
												destructive
												quiet
												send={() => client.renounceRole(entry.name, holder)}
												confirm={{
													title: `Renounce ${entry.name}`,
													effect: `Your wallet gives up the ability to ${description.may}. Only ROLE_ADMIN can grant it back.`,
													confirmLabel: "Renounce",
												}}
											/>
										)}
									</HStack>
								</Stack>
							);
						})}
					</Stack>
				)}
			</Table.Cell>
			<Table.Cell
				verticalAlign="top"
				fontSize="sm"
				color="fg.muted"
				minW="xs"
				whiteSpace="normal"
			>
				<Text>May {description.may}.</Text>
				<Text mt="1">
					May{" "}
					<Text as="span" fontWeight="semibold" color="fg">
						not
					</Text>{" "}
					{description.mayNot}.
				</Text>
			</Table.Cell>
		</Table.Row>
	);
}

/**
 * DEFAULT_ADMIN_ROLE is never granted (D4): a holder is a superuser by another name. It is its own
 * admin, so only a holder can revoke it — from another holder, or by renouncing.
 */
function DefaultAdminCard({
	client,
	holders,
}: {
	client: GianoPaymasterClient;
	holders: readonly Address[];
}) {
	const { wallet } = useConsole();
	if (holders.length === 0)
		return (
			<HStack
				gap="3"
				flexWrap="wrap"
				borderWidth="1px"
				rounded="lg"
				bg="surface"
				px="4"
				py="3"
				fontSize="sm"
				data-testid="default-admin"
			>
				<Text fontFamily="mono" fontWeight="medium">
					DEFAULT_ADMIN_ROLE
				</Text>
				<StatusText tone="green">held by nobody</StatusText>
				<Text color="fg.muted">
					There is no superuser: every power goes through a named role.
				</Text>
			</HStack>
		);
	const youHold =
		wallet !== undefined &&
		holders.some((holder) => isAddressEqual(holder, wallet.address));
	return (
		<Alert.Root status="error" data-testid="default-admin">
			<Alert.Indicator />
			<Alert.Content>
				<Alert.Title>DEFAULT_ADMIN_ROLE is held</Alert.Title>
				<Alert.Description>
					<Stack gap="3" mt="1">
						<Text>
							It should be held by nobody. Its holders can grant themselves
							anything the named roles divide up. Only a holder can revoke it.
						</Text>
						{holders.map((holder) => {
							const isYou =
								wallet !== undefined && isAddressEqual(holder, wallet.address);
							return (
								<HStack key={holder} gap="3" flexWrap="wrap">
									<AddressLabel
										address={holder}
										label="DEFAULT_ADMIN_ROLE holder"
									/>
									<ActionButton
										target={{
											gate: {
												allowed: youHold,
												reason:
													"Needs DEFAULT_ADMIN_ROLE: only a holder can revoke it.",
											},
										}}
										label={isYou ? "Renounce" : "Revoke"}
										size="xs"
										destructive
										send={() =>
											isYou
												? client.renounceRole("DEFAULT_ADMIN_ROLE", holder)
												: client.revokeRole("DEFAULT_ADMIN_ROLE", holder)
										}
										confirm={{
											title: isYou
												? "Renounce DEFAULT_ADMIN_ROLE"
												: "Revoke DEFAULT_ADMIN_ROLE",
											effect: `${isYou ? "Your wallet" : holder} will no longer hold DEFAULT_ADMIN_ROLE. Nothing can grant it again except another holder.`,
											confirmLabel: isYou ? "Renounce" : "Revoke",
										}}
									/>
								</HStack>
							);
						})}
					</Stack>
				</Alert.Description>
			</Alert.Content>
		</Alert.Root>
	);
}

/** Grant a role, or rotate it from one holder to another in one operation (openspec N5). */
function ChangeCard({
	client,
	roles,
}: {
	client: GianoPaymasterClient;
	roles: readonly (RoleHolders & { name: PaymasterRoleName })[];
}) {
	const [role, setRole] = useState<PaymasterRoleName>("TENANT_ADMIN_ROLE");
	const grantTo = useAddressInput();
	const rotateTo = useAddressInput();
	const holders = roles.find((entry) => entry.name === role)?.holders ?? [];
	const [from, setFrom] = useState<string>("");
	const rotateFrom = holders.find((holder) => holder === from) ?? holders[0];
	const grantee = grantTo.value;
	// Rotating a holder to itself would grant nothing and then revoke it: the role left with nobody.
	const sameHolder =
		rotateTo.value !== undefined &&
		rotateFrom !== undefined &&
		isAddressEqual(rotateTo.value, rotateFrom);
	const successor = sameHolder ? undefined : rotateTo.value;

	return (
		<SectionCard
			title="Change a role"
			subtitle="Role changes are timelocked: a wallet holding ROLE_ADMIN sends them, and anyone else proposes them to the timelock. Revoke from a holder's row above."
		>
			<Stack gap="5">
				<Field.Root maxW="sm">
					<Field.Label fontSize="sm">Role</Field.Label>
					<NativeSelect.Root size="sm">
						<NativeSelect.Field
							value={role}
							onChange={(event) => {
								setRole(event.currentTarget.value as PaymasterRoleName);
								setFrom("");
							}}
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
				<SimpleGrid columns={{ base: 1, md: 2 }} gap="5">
					<Stack gap="2">
						<Text fontWeight="medium" fontSize="sm">
							Grant
						</Text>
						<AddressInput input={grantTo} label="Grant to" />
						<ActionButton
							target={{ operation: "grantRole" }}
							label="Grant"
							send={grantee ? () => client.grantRole(role, grantee) : undefined}
							proposal={
								grantee
									? { kind: "grantRole", role, account: grantee }
									: undefined
							}
							onDone={grantTo.clear}
						/>
					</Stack>
					<Stack gap="2">
						<Text fontWeight="medium" fontSize="sm">
							Rotate
						</Text>
						{holders.length === 0 ? (
							<Text fontSize="sm" color="fg.muted">
								Nobody holds {role}, so there is nothing to rotate. Grant it
								instead.
							</Text>
						) : (
							<>
								<Field.Root>
									<Field.Label fontSize="sm">From</Field.Label>
									<NativeSelect.Root size="sm">
										<NativeSelect.Field
											value={rotateFrom}
											onChange={(event) => setFrom(event.currentTarget.value)}
											fontFamily="mono"
										>
											{holders.map((holder) => (
												<option key={holder} value={holder}>
													{holder}
												</option>
											))}
										</NativeSelect.Field>
										<NativeSelect.Indicator />
									</NativeSelect.Root>
								</Field.Root>
								<AddressInput
									input={rotateTo}
									label="To"
									helper={
										sameHolder ? (
											<Text as="span" color="red.fg">
												That is the holder it rotates from: rotating to itself
												would leave the role with nobody.
											</Text>
										) : undefined
									}
								/>
								<Box>
									<ActionButton
										target={{ operation: "grantRole" }}
										label="Rotate"
										send={
											successor && rotateFrom
												? async () => {
														// Grant first, so the role is never held by nobody in between.
														const granted = await client.grantRole(
															role,
															successor,
														);
														// Revoke only once the grant has succeeded: mined is not the same.
														const receipt = await granted.wait();
														if (receipt.status !== "success")
															throw new Error(
																`The grant to ${successor} (${granted.hash}) reverted, so ${rotateFrom} keeps the role; nothing was revoked.`,
															);
														return client.revokeRole(role, rotateFrom);
													}
												: undefined
										}
										proposal={
											successor && rotateFrom
												? {
														kind: "rotateRole",
														role,
														from: rotateFrom,
														to: successor,
													}
												: undefined
										}
										onDone={rotateTo.clear}
									/>
								</Box>
								<Text fontSize="xs" color="fg.muted">
									Proposed, the grant and the revoke are one operation. Sent,
									they are two transactions, the grant first.
								</Text>
							</>
						)}
					</Stack>
				</SimpleGrid>
			</Stack>
		</SectionCard>
	);
}
