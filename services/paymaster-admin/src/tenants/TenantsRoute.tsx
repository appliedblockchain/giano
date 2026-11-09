import type { GianoPaymasterClient } from "@appliedblockchain/giano-paymaster-sdk";
import {
	Button,
	CloseButton,
	Dialog,
	Heading,
	HStack,
	Portal,
	Spinner,
	Stack,
	Text,
} from "@chakra-ui/react";
import { useState } from "react";
import { getAdminConfig } from "../config";
import { Link, TAB_PATHS } from "../lib/router";
import type { TenantRow } from "../lib/tenants";
import { CreateTenantDialog } from "../platform/CreateTenantDialog";
import type { PlatformAreaProps } from "../platform/shared";
import { RegisterById } from "./OnChainCard";
import { TenantPage } from "./TenantPage";
import { TenantsList } from "./TenantsList";
import type { Registry } from "./useRegistry";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * The Tenants tab: the list at `/tenants`, one tenant's page at `/tenants/<slug>` — or
 * `/tenants/<id>` for a tenant with no registry row. Both read the same join, so a tenant's page
 * and its row cannot disagree.
 */
export function TenantsRoute({
	param,
	client,
	rows,
	registry,
	rosterOnChain,
	lastUpdated,
	platformProps,
}: {
	/** The slug or id from the path; undefined on the list. */
	param: string | undefined;
	/** Undefined while the paymaster has not been read: the registry still shows, its chain side unknown. */
	client: GianoPaymasterClient | undefined;
	/** The registry joined to the roster, as the console computes it once for the tab bar too. */
	rows: readonly TenantRow[];
	registry: Registry;
	rosterOnChain: boolean;
	lastUpdated: Date | undefined;
	platformProps: PlatformAreaProps;
}) {
	const { platformApi } = getAdminConfig();
	const [creating, setCreating] = useState(false);
	const [registering, setRegistering] = useState(false);

	if (param !== undefined) {
		const key = param.toLowerCase();
		const byId = (candidate: TenantRow) =>
			candidate.id === key || candidate.onChain?.id.toLowerCase() === key;
		const bySlug = (candidate: TenantRow) => candidate.registry?.slug === param;
		// A path shaped like a tenant id is matched by id first, so a slug shaped like a UUID cannot
		// stand in for an on-chain-only tenant at /tenants/<its id>.
		const row = UUID.test(param)
			? (rows.find(byId) ?? rows.find(bySlug))
			: (rows.find(bySlug) ?? rows.find(byId));
		if (row)
			return (
				<TenantPage
					key={row.id}
					row={row}
					// A tenant missing from a registry not read in full may be one of its deleted tenants.
					registryComplete={
						!platformApi ||
						(registry.tenants !== undefined && !registry.deletedError)
					}
					client={client}
					platformProps={platformProps}
					lastUpdated={lastUpdated}
					onRegistryChanged={() => void registry.reload()}
				/>
			);
		if (platformApi && registry.tenants === undefined && !registry.error)
			return (
				<HStack py="16" justify="center">
					<Spinner />
				</HStack>
			);
		return (
			<Stack align="center" py="16" gap="3">
				<Heading size="md">No tenant {param}</Heading>
				<Text color="fg.muted">
					No tenant has that slug or id
					{platformApi ? " in the registry or" : ""} on this paymaster.
				</Text>
				<Link to={TAB_PATHS.tenants} color="brand.fg" fontWeight="medium">
					All tenants
				</Link>
			</Stack>
		);
	}

	return (
		<>
			<TenantsList
				rows={rows}
				registry={registry}
				rosterOnChain={rosterOnChain}
				onCreate={() => setCreating(true)}
				onRegister={() => setRegistering(true)}
			/>
			{platformApi && (
				<CreateTenantDialog
					{...platformProps}
					open={creating}
					onClose={() => setCreating(false)}
					onCreated={() => void registry.reload()}
				/>
			)}
			<Dialog.Root
				open={registering}
				onOpenChange={(event) => !event.open && setRegistering(false)}
			>
				<Portal>
					<Dialog.Backdrop />
					<Dialog.Positioner>
						<Dialog.Content>
							<Dialog.Header>
								<Dialog.Title>Register a tenant</Dialog.Title>
							</Dialog.Header>
							<Dialog.Body>
								{client ? (
									<RegisterById client={client} />
								) : (
									<Text color="fg.muted">
										The paymaster has not been read yet, so there is nothing to
										register on.
									</Text>
								)}
							</Dialog.Body>
							<Dialog.Footer>
								<Button variant="ghost" onClick={() => setRegistering(false)}>
									Close
								</Button>
							</Dialog.Footer>
							<Dialog.CloseTrigger asChild>
								<CloseButton size="sm" />
							</Dialog.CloseTrigger>
						</Dialog.Content>
					</Dialog.Positioner>
				</Portal>
			</Dialog.Root>
		</>
	);
}
