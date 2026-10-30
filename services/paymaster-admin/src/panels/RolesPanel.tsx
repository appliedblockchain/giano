import {
	type GianoPaymasterClient,
	type PaymasterRoleName,
	ROLE_DESCRIPTIONS,
	type RoleHolders,
} from "@appliedblockchain/giano-paymaster-sdk";
import {
	Alert,
	Badge,
	Box,
	Button,
	HStack,
	Input,
	NativeSelect,
	Stack,
	Table,
	Text,
} from "@chakra-ui/react";
import { useState } from "react";
import { type Address, isAddress, isAddressEqual } from "viem";
import { Copyable, SectionCard } from "../components/ui";
import { useWrite } from "../hooks/useWrite";
import type { Propose } from "../lib/proposals";

type Props = {
	client: GianoPaymasterClient;
	roles: readonly RoleHolders[];
	myRoles: readonly PaymasterRoleName[];
	account: Address | undefined;
	refresh: () => Promise<void>;
	/** Set when the deployment has a timelock: role changes the wallet cannot send are proposed. */
	propose?: Propose;
	/** The configured timelock, so a holder that is the timelock can say so. */
	timelockAddress?: Address;
};

/**
 * Role holders, and what each role is actually for.
 *
 * The "may not" column is the point rather than decoration: the security argument is a set of
 * pairs — the fee admin cannot collect the fees it sets, the fee collector cannot change the rate,
 * no role at all can reach a tenant balance — and an operator reviewing holders needs to see the
 * pair to know whether a grant is safe.
 *
 * Each role also says whether it is timelocked (G9). On a handed-off deployment the timelock holds
 * ROLE_ADMIN, so granting and revoking are themselves timelocked: a wallet that holds ROLE_ADMIN (a
 * devnet key) sends them directly, and anyone else builds a proposal for the timelock instead of a
 * transaction that would revert.
 */
export function RolesPanel({
	client,
	roles,
	myRoles,
	account,
	refresh,
	propose,
	timelockAddress,
}: Props) {
	const { run, busy } = useWrite(refresh);
	const canGrant = myRoles.includes("ROLE_ADMIN");
	const canPropose = !canGrant && propose !== undefined;

	const [role, setRole] = useState<PaymasterRoleName>("TENANT_ADMIN_ROLE");
	const [target, setTarget] = useState("");
	const [problem, setProblem] = useState<string>();

	const defaultAdmin = roles.find(
		(entry) => entry.name === "DEFAULT_ADMIN_ROLE",
	);

	const proposeChange = (kind: "grantRole" | "revokeRole") => {
		if (!propose) return;
		if (!isAddress(target)) {
			const message = `"${target}" is not an address.`;
			setProblem(message);
			console.error(`[paymaster-admin] Could not propose ${kind}: ${message}`);
			return;
		}
		setProblem(undefined);
		propose({ kind, role, account: target });
	};

	return (
		<Stack gap="4">
			{defaultAdmin && defaultAdmin.holders.length > 0 && (
				<Alert.Root status="error">
					<Alert.Indicator />
					<Alert.Content>
						<Alert.Title>DEFAULT_ADMIN_ROLE is held</Alert.Title>
						<Alert.Description>
							{defaultAdmin.holders.join(", ")} — this is a superuser by another
							name. The design grants every power through its own named role
							instead; revoke it.
						</Alert.Description>
					</Alert.Content>
				</Alert.Root>
			)}

			<SectionCard
				title="Roles"
				subtitle="There is no owner and no superuser. Every role is administered by ROLE_ADMIN. Timelocked roles are held by the timelock on a handed-off deployment, so their functions wait out a public delay; immediate roles stay on operational keys."
			>
				<Table.ScrollArea borderWidth="1px" rounded="md">
					<Table.Root size="sm">
						<Table.Header>
							<Table.Row>
								<Table.ColumnHeader>Role</Table.ColumnHeader>
								<Table.ColumnHeader>Holders</Table.ColumnHeader>
								<Table.ColumnHeader>
									What it can and cannot do
								</Table.ColumnHeader>
							</Table.Row>
						</Table.Header>
						<Table.Body>
							{roles
								.filter((entry) => entry.name !== "DEFAULT_ADMIN_ROLE")
								.map((entry) => {
									const description =
										ROLE_DESCRIPTIONS[entry.name as PaymasterRoleName];
									return (
										<Table.Row key={entry.role}>
											<Table.Cell>
												<Stack gap="1">
													<Text fontWeight="medium" fontSize="sm">
														{entry.name}
													</Text>
													<HStack gap="1" flexWrap="wrap">
														{description?.timelocked ? (
															<Badge
																colorPalette="purple"
																variant="subtle"
																size="sm"
																title="Held by the timelock on a handed-off deployment: its functions wait out a public delay"
															>
																timelocked
															</Badge>
														) : (
															<Badge
																colorPalette="gray"
																variant="subtle"
																size="sm"
																title="Stays on an operational key: its functions take effect immediately"
															>
																immediate
															</Badge>
														)}
														{myRoles.includes(
															entry.name as PaymasterRoleName,
														) && (
															<Badge
																colorPalette="brand"
																variant="subtle"
																size="sm"
															>
																you hold this
															</Badge>
														)}
													</HStack>
												</Stack>
											</Table.Cell>
											<Table.Cell>
												{entry.holders.length === 0 ? (
													<Text fontSize="sm" color="fg.muted">
														nobody
													</Text>
												) : (
													<Stack gap="1">
														{entry.holders.map((holder) => (
															<HStack key={holder} gap="2" flexWrap="wrap">
																<Copyable value={holder} label={entry.name} />
																{timelockAddress &&
																	isAddressEqual(holder, timelockAddress) && (
																		<Badge
																			colorPalette="purple"
																			variant="outline"
																			size="sm"
																		>
																			the timelock
																		</Badge>
																	)}
																{canGrant && (
																	<Button
																		size="xs"
																		variant="ghost"
																		colorPalette="red"
																		disabled={busy}
																		onClick={() =>
																			void run(`Revoke ${entry.name}`, () =>
																				client.revokeRole(
																					entry.name as PaymasterRoleName,
																					holder,
																				),
																			)
																		}
																	>
																		revoke
																	</Button>
																)}
																{canPropose && (
																	<Button
																		size="xs"
																		variant="ghost"
																		colorPalette="red"
																		title="revokeRole is timelocked: build the proposal for the timelock"
																		onClick={() =>
																			propose?.({
																				kind: "revokeRole",
																				role: entry.name as PaymasterRoleName,
																				account: holder,
																			})
																		}
																	>
																		propose revoke
																	</Button>
																)}
															</HStack>
														))}
													</Stack>
												)}
											</Table.Cell>
											<Table.Cell fontSize="sm" color="fg.muted">
												<Text>May {description?.may}.</Text>
												<Text mt="0.5">
													May{" "}
													<Text as="span" fontWeight="medium">
														not
													</Text>{" "}
													{description?.mayNot}.
												</Text>
											</Table.Cell>
										</Table.Row>
									);
								})}
						</Table.Body>
					</Table.Root>
				</Table.ScrollArea>

				{!defaultAdmin?.holders.length && (
					<Text fontSize="xs" color="accent.fg" mt="3">
						✓ DEFAULT_ADMIN_ROLE is held by nobody — there is no superuser.
					</Text>
				)}
			</SectionCard>

			{(canGrant || canPropose) && (
				<SectionCard
					title={canGrant ? "Grant a role" : "Propose a role change"}
					subtitle={
						canGrant
							? "You hold ROLE_ADMIN, so this sends directly. Role changes are timelocked: on a handed-off deployment only the timelock holds ROLE_ADMIN, and they are proposed instead."
							: "grantRole and revokeRole are timelocked. This builds the proposal and the Safe batch for the timelock; nothing is sent from here."
					}
				>
					<HStack gap="3" flexWrap="wrap" align="flex-end">
						<Box minW="14rem">
							<Text fontSize="sm" mb="1">
								Role
							</Text>
							<NativeSelect.Root size="sm">
								<NativeSelect.Field
									value={role}
									onChange={(event) =>
										setRole(event.currentTarget.value as PaymasterRoleName)
									}
								>
									{roles
										.filter((entry) => entry.name !== "DEFAULT_ADMIN_ROLE")
										.map((entry) => (
											<option key={entry.role} value={entry.name}>
												{entry.name}
											</option>
										))}
								</NativeSelect.Field>
								<NativeSelect.Indicator />
							</NativeSelect.Root>
						</Box>
						<Box flex="1" minW="20rem">
							<Text fontSize="sm" mb="1">
								Address
							</Text>
							<Input
								size="sm"
								value={target}
								onChange={(event) => setTarget(event.target.value)}
								placeholder="0x…"
							/>
						</Box>
						{canGrant ? (
							<Button
								size="sm"
								colorPalette="brand"
								disabled={busy || !target}
								onClick={() =>
									void run(`Grant ${role}`, () =>
										client.grantRole(role, target as Address),
									)
								}
							>
								Grant
							</Button>
						) : (
							<>
								<Button
									size="sm"
									colorPalette="brand"
									disabled={!target}
									onClick={() => proposeChange("grantRole")}
								>
									Propose grant
								</Button>
								<Button
									size="sm"
									variant="outline"
									colorPalette="red"
									disabled={!target}
									onClick={() => proposeChange("revokeRole")}
								>
									Propose revoke
								</Button>
							</>
						)}
					</HStack>
					{problem && (
						<Text fontSize="xs" color="red.fg" mt="2">
							{problem}
						</Text>
					)}
					{account && canGrant && (
						<Text fontSize="xs" color="fg.muted" mt="3">
							Signing as {account}.
						</Text>
					)}
				</SectionCard>
			)}
		</Stack>
	);
}
