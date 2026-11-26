import {
	Alert,
	Badge,
	Button,
	Field,
	HStack,
	Input,
	NativeSelect,
	SimpleGrid,
	Stack,
	Table,
	Text,
	Textarea,
} from "@chakra-ui/react";
import { useCallback, useEffect, useState } from "react";
import { LuHistory, LuPencil, LuRefreshCw } from "react-icons/lu";
import { notifySuccess, SectionCard } from "../components/ui";
import {
	CAP_FIELDS,
	CAP_LABELS,
	CHAIN_LIST_MODE_LABELS,
	type ChainPolicyForm,
	chainPolicyFormProblems,
	chainPolicyToForm,
	describeChainPolicySource,
	describeChainPolicyValue,
	formToChainPolicy,
	LIST_FIELDS,
	LIST_LABELS,
	type ListForm,
	overriddenFields,
} from "../lib/chain-policy";
import type {
	ChainPolicyHistoryEntry,
	ChainPolicyView,
} from "../lib/platform-api";
import { usePlatform } from "../lib/platform-session";
import { ActionDialog, usePlatformAction } from "./LifecycleDialogs";
import { actorLabel, issuesByField } from "./shared";

const FIELDS = [...CAP_FIELDS, ...LIST_FIELDS] as const;
const LABELS: Record<string, string> = { ...CAP_LABELS, ...LIST_LABELS };

const log = (message: string, data?: unknown) =>
	console.log(`[paymaster-admin] relay policy: ${message}`, data ?? "");

/**
 * Each served chain's relay policy (openspec chain-relay-policy-console): the caps and allowlists the
 * relay applies to every tenant on the chain, unless the tenant's own policy narrows them. Stored in
 * wallet-api's database and edited here; a field GIANO_CHAINS or an env var overrides is shown with
 * its source and cannot be edited here. A chain with a problem has its operations refused, and the
 * problem says how to fix it.
 */
export function RelayPolicyTab() {
	const { run } = usePlatform();
	const [chains, setChains] = useState<ChainPolicyView[]>();
	const [loading, setLoading] = useState(false);
	const [loadError, setLoadError] = useState<string>();
	const [editing, setEditing] = useState<ChainPolicyView>();
	const [saved, setSaved] = useState<Record<number, string>>({});

	const load = useCallback(async () => {
		setLoading(true);
		try {
			const result = await run((api) => api.chainPolicies());
			if (!result) return; // the session ended; the area is back on sign-in
			if (!result.ok) {
				console.error(
					"[paymaster-admin] relay policy: could not read",
					result.error,
				);
				return setLoadError(result.error.message);
			}
			setLoadError(undefined);
			setChains(result.value.chains);
			log("read", result.value.chains);
		} catch (cause) {
			console.error("[paymaster-admin] relay policy: could not read", cause);
			setLoadError(cause instanceof Error ? cause.message : String(cause));
		} finally {
			setLoading(false);
		}
	}, [run]);

	useEffect(() => {
		void load();
	}, [load]);

	return (
		<Stack gap="4">
			<SectionCard
				title="Relay policy"
				subtitle="What wallet-api relays on each chain, for every tenant: gas and fee caps, and which contracts and paymasters an operation may use. A tenant's own policy can narrow these per chain. An edit applies to the next operation."
				action={
					<Button
						size="sm"
						variant="ghost"
						onClick={() => void load()}
						loading={loading}
						aria-label="Refresh relay policy"
					>
						<LuRefreshCw />
					</Button>
				}
			>
				{loadError ? (
					<Alert.Root status="error" size="sm">
						<Alert.Indicator />
						<Alert.Content>
							<Alert.Title>Could not read the relay policy</Alert.Title>
							<Alert.Description overflowWrap="anywhere">
								{loadError}
							</Alert.Description>
						</Alert.Content>
					</Alert.Root>
				) : chains?.length === 0 ? (
					<Text color="fg.muted">wallet-api serves no chain.</Text>
				) : !chains ? (
					<Text color="fg.muted">Reading…</Text>
				) : null}
			</SectionCard>
			{chains?.map((chain) => (
				<ChainCard
					key={chain.chainId}
					chain={chain}
					saved={saved[chain.chainId]}
					onEdit={() => setEditing(chain)}
				/>
			))}
			{editing && (
				<EditChainPolicyDialog
					chain={editing}
					onClose={() => setEditing(undefined)}
					onSaved={(view) => {
						setChains((current) =>
							current?.map((chain) =>
								chain.chainId === view.chainId ? view : chain,
							),
						);
						setSaved((current) => ({
							...current,
							[view.chainId]: `Saved as version ${view.version} at ${new Date().toLocaleTimeString()}.`,
						}));
						setEditing(undefined);
					}}
				/>
			)}
		</Stack>
	);
}

function ChainCard({
	chain,
	saved,
	onEdit,
}: {
	chain: ChainPolicyView;
	saved?: string;
	onEdit: () => void;
}) {
	const [showHistory, setShowHistory] = useState(false);
	const refused = chain.problems.length > 0;
	return (
		<SectionCard
			title={`${chain.name} (${chain.chainId})`}
			subtitle={
				chain.version === 0
					? "No stored policy."
					: `Version ${chain.version} · ${actorLabel(chain.updatedBy ?? "")} · ${chain.updatedAt ? new Date(chain.updatedAt).toLocaleString() : ""}`
			}
			action={
				<HStack>
					<Button
						size="sm"
						variant="ghost"
						onClick={() => setShowHistory((open) => !open)}
					>
						<LuHistory /> History
					</Button>
					<Button size="sm" colorPalette="brand" onClick={onEdit}>
						<LuPencil /> Edit
					</Button>
				</HStack>
			}
		>
			<Stack gap="3" data-testid={`relay-policy-${chain.chainId}`}>
				{refused && (
					<Alert.Root status="error" size="sm">
						<Alert.Indicator />
						<Alert.Content>
							<Alert.Title>
								Operations on this chain are refused (rule chain-policy)
							</Alert.Title>
							<Alert.Description overflowWrap="anywhere">
								<Stack gap="1">
									{chain.problems.map((problem) => (
										<Text key={problem}>{problem}</Text>
									))}
								</Stack>
							</Alert.Description>
						</Alert.Content>
					</Alert.Root>
				)}
				{saved && (
					<Text fontSize="sm" color="green.fg">
						{saved}
					</Text>
				)}
				<Table.ScrollArea borderWidth="1px" rounded="md">
					<Table.Root size="sm">
						<Table.Header>
							<Table.Row>
								<Table.ColumnHeader>Field</Table.ColumnHeader>
								<Table.ColumnHeader>Applies</Table.ColumnHeader>
								<Table.ColumnHeader>From</Table.ColumnHeader>
							</Table.Row>
						</Table.Header>
						<Table.Body>
							{FIELDS.map((field) => {
								const view = chain.fields[field];
								if (!view) return null;
								return (
									<Table.Row key={field}>
										<Table.Cell>{LABELS[field]}</Table.Cell>
										<Table.Cell
											fontFamily="mono"
											fontSize="xs"
											overflowWrap="anywhere"
										>
											{describeChainPolicyValue(field, view.effective)}
										</Table.Cell>
										<Table.Cell>
											<SourceBadge field={view} />
										</Table.Cell>
									</Table.Row>
								);
							})}
						</Table.Body>
					</Table.Root>
				</Table.ScrollArea>
				{showHistory && <ChainHistory chainId={chain.chainId} />}
			</Stack>
		</SectionCard>
	);
}

function SourceBadge({ field }: { field: ChainPolicyView["fields"][string] }) {
	const palette = {
		stored: "gray",
		override: "purple",
		fallback: "orange",
		undecided: "red",
	}[field.source];
	return (
		<Badge size="sm" variant="subtle" colorPalette={palette}>
			{describeChainPolicySource(field)}
		</Badge>
	);
}

function ChainHistory({ chainId }: { chainId: number }) {
	const { run } = usePlatform();
	const [entries, setEntries] = useState<ChainPolicyHistoryEntry[]>();
	const [error, setError] = useState<string>();
	useEffect(() => {
		void (async () => {
			const result = await run((api) => api.chainPolicyHistory(chainId));
			if (!result) return;
			if (!result.ok) {
				console.error(
					"[paymaster-admin] relay policy: could not read the history",
					result.error,
				);
				return setError(result.error.message);
			}
			setEntries(result.value.entries);
		})();
	}, [run, chainId]);
	if (error)
		return (
			<Text fontSize="sm" color="red.fg">
				Could not read the history: {error}
			</Text>
		);
	if (!entries) return <Text color="fg.muted">Reading the history…</Text>;
	return (
		<Stack gap="2">
			{entries.map((entry) => (
				<Stack key={entry.id} gap="0" fontSize="xs">
					<Text>
						<b>{entry.action === "seed" ? "Seeded" : "Changed"}</b> by{" "}
						{actorLabel(entry.actor)} ·{" "}
						{new Date(entry.createdAt).toLocaleString()}
					</Text>
					<Text fontFamily="mono" color="fg.muted" overflowWrap="anywhere">
						{JSON.stringify(entry.after)}
					</Text>
				</Stack>
			))}
		</Stack>
	);
}

function EditChainPolicyDialog({
	chain,
	onClose,
	onSaved,
}: {
	chain: ChainPolicyView;
	onClose: () => void;
	onSaved: (view: ChainPolicyView) => void;
}) {
	const { act, busy, error } = usePlatformAction();
	const [form, setForm] = useState<ChainPolicyForm>(() =>
		chainPolicyToForm(chain.stored),
	);
	const locked = overriddenFields(chain);
	const problems = chainPolicyFormProblems(form);
	const issues = issuesByField(error);

	const save = async () => {
		const policy = formToChainPolicy(form);
		log("saving", { chainId: chain.chainId, version: chain.version, policy });
		const result = await act((api) =>
			api.replaceChainPolicy(chain.chainId, chain.version, policy),
		);
		if (!result) return; // the session ended
		if (!result.ok) {
			console.error(
				"[paymaster-admin] relay policy: save refused",
				result.error,
			);
			return;
		}
		log("saved", result.value);
		notifySuccess(
			`Relay policy saved for ${chain.name}`,
			`Version ${result.value.version}`,
		);
		onSaved(result.value);
	};

	const setList = (field: (typeof LIST_FIELDS)[number], next: ListForm) =>
		setForm((current) => ({ ...current, [field]: next }));

	return (
		<ActionDialog
			open
			onClose={onClose}
			title={`Relay policy: ${chain.name} (${chain.chainId})`}
			confirmLabel="Save"
			busy={busy}
			disabled={problems.length > 0}
			error={error}
			onConfirm={() => void save()}
		>
			<Stack gap="3">
				<Text fontSize="sm" color="fg.muted">
					Empty or "Not set" stores nothing for the field: outside production
					the relay then uses its fallback; in production every operation on
					this chain is refused until it is set.
				</Text>
				<SimpleGrid columns={{ base: 1, md: 2 }} gap="3">
					{CAP_FIELDS.map((field) => (
						<Field.Root
							key={field}
							disabled={locked.has(field)}
							invalid={!!issues[field]}
						>
							<Field.Label fontSize="sm">{CAP_LABELS[field]}</Field.Label>
							<Input
								size="sm"
								fontFamily="mono"
								inputMode="numeric"
								value={form[field]}
								onChange={(event) =>
									setForm((current) => ({
										...current,
										[field]: event.target.value,
									}))
								}
								placeholder="not set"
							/>
							<FieldNote
								locked={locked.has(field)}
								overriddenBy={chain.fields[field]?.overriddenBy}
								issues={issues[field]}
							/>
						</Field.Root>
					))}
					{LIST_FIELDS.map((field) => (
						<Field.Root
							key={field}
							disabled={locked.has(field)}
							invalid={!!issues[field]}
						>
							<Field.Label fontSize="sm">{LIST_LABELS[field]}</Field.Label>
							<NativeSelect.Root size="sm" disabled={locked.has(field)}>
								<NativeSelect.Field
									aria-label={LIST_LABELS[field]}
									value={form[field].mode}
									onChange={(event) =>
										setList(field, {
											...form[field],
											mode: event.currentTarget.value as ListForm["mode"],
										})
									}
								>
									{Object.entries(CHAIN_LIST_MODE_LABELS).map(
										([mode, label]) => (
											<option key={mode} value={mode}>
												{label}
											</option>
										),
									)}
								</NativeSelect.Field>
								<NativeSelect.Indicator />
							</NativeSelect.Root>
							{form[field].mode === "only" && (
								<Textarea
									mt="2"
									size="sm"
									rows={3}
									fontFamily="mono"
									placeholder="0x…, one per line"
									value={form[field].text}
									disabled={locked.has(field)}
									onChange={(event) =>
										setList(field, { mode: "only", text: event.target.value })
									}
								/>
							)}
							<FieldNote
								locked={locked.has(field)}
								overriddenBy={chain.fields[field]?.overriddenBy}
								issues={issues[field]}
							/>
						</Field.Root>
					))}
				</SimpleGrid>
				{problems.length > 0 && (
					<Alert.Root status="warning" size="sm">
						<Alert.Indicator />
						<Alert.Content>
							<Alert.Title>Fix these before saving</Alert.Title>
							<Alert.Description>
								<Stack gap="1">
									{problems.map((problem) => (
										<Text key={problem}>{problem}</Text>
									))}
								</Stack>
							</Alert.Description>
						</Alert.Content>
					</Alert.Root>
				)}
				{error?.error === "version-mismatch" && (
					<Text fontSize="sm" color="red.fg">
						Close this dialog and refresh to edit the current version.
					</Text>
				)}
			</Stack>
		</ActionDialog>
	);
}

function FieldNote({
	locked,
	overriddenBy,
	issues,
}: {
	locked: boolean;
	overriddenBy?: string | null;
	issues?: string[];
}) {
	if (issues?.length)
		return <Field.ErrorText>{issues.join(" ")}</Field.ErrorText>;
	if (locked)
		return (
			<Field.HelperText>
				Overridden by {overriddenBy ?? "the deployment"}: change it there. The
				stored value applies once the override is removed.
			</Field.HelperText>
		);
	return null;
}
