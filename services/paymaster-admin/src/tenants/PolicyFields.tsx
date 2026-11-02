import {
	Box,
	Button,
	DataList,
	Field,
	HStack,
	Input,
	NativeSelect,
	SimpleGrid,
	Stack,
	Text,
	Textarea,
} from "@chakra-ui/react";
import { LuPlus, LuTrash2 } from "react-icons/lu";
import { getAdminConfig } from "../config";
import {
	CAP_FIELDS,
	CAP_LABELS,
	emptyChain,
	LIST_FIELDS,
	LIST_LABELS,
	type ListMode,
	type PerChainForm,
	type PolicyForm,
	policyProblems,
} from "../lib/policy";

/** wallet-api's 400 for a policy names its path below `/policy`; shown on the policy as a whole. */
type Props = {
	value: PolicyForm;
	onChange: (next: PolicyForm) => void;
	error?: string;
};

/**
 * The sponsorship policy as fields (openspec K11): the caps that apply on every chain, the relay
 * rate limit, and a section per chain for that chain's caps and allowlists. Every field is optional:
 * left empty, it inherits the deployment default.
 */
export function PolicyFields({ value, onChange, error }: Props) {
	const knownChains = getAdminConfig().deployments.map(
		(deployment) => deployment.chainId,
	);
	const setChain = (index: number, chain: PerChainForm) =>
		onChange({
			...value,
			perChain: value.perChain.map((entry, at) =>
				at === index ? chain : entry,
			),
		});
	const unused = knownChains.find(
		(chainId) =>
			!value.perChain.some((entry) => entry.chainId === String(chainId)),
	);

	return (
		<Stack gap="3">
			<Text fontWeight="medium" fontSize="sm">
				Sponsorship policy
			</Text>
			<Text fontSize="xs" color="fg.muted">
				Per-tenant overrides of the deployment's defaults. Leave a field empty
				to inherit the default. wallet-api checks every value on save.
			</Text>
			<SimpleGrid columns={{ base: 1, md: 2 }} gap="3">
				{CAP_FIELDS.map((field) => (
					<Field.Root key={field}>
						<Field.Label fontSize="sm">{CAP_LABELS[field]}</Field.Label>
						<Input
							size="sm"
							fontFamily="mono"
							inputMode="numeric"
							value={value[field]}
							onChange={(event) =>
								onChange({ ...value, [field]: event.target.value })
							}
							placeholder="default"
						/>
					</Field.Root>
				))}
				<Field.Root>
					<Field.Label fontSize="sm">Relay rate limit (per minute)</Field.Label>
					<Input
						size="sm"
						fontFamily="mono"
						inputMode="numeric"
						value={value.relayRateLimitPerMinute}
						onChange={(event) =>
							onChange({
								...value,
								relayRateLimitPerMinute: event.target.value,
							})
						}
						placeholder="default"
					/>
					<Field.HelperText>Shared across every chain.</Field.HelperText>
				</Field.Root>
			</SimpleGrid>

			{value.perChain.map((chain, index) => (
				// biome-ignore lint/suspicious/noArrayIndexKey: the chain id is what the operator is typing, so keying on it would remount the field each keystroke; the inputs are controlled
				<Box key={index} borderWidth="1px" rounded="md" p="3">
					<HStack justify="space-between" mb="2">
						<Field.Root maxW="40">
							<Field.Label fontSize="sm">Chain id</Field.Label>
							<Input
								size="sm"
								fontFamily="mono"
								inputMode="numeric"
								value={chain.chainId}
								onChange={(event) =>
									setChain(index, { ...chain, chainId: event.target.value })
								}
							/>
						</Field.Root>
						<Button
							size="xs"
							variant="ghost"
							colorPalette="red"
							aria-label={`Remove the chain ${chain.chainId} section`}
							onClick={() =>
								onChange({
									...value,
									perChain: value.perChain.filter((_, at) => at !== index),
								})
							}
						>
							<LuTrash2 /> Remove
						</Button>
					</HStack>
					<SimpleGrid columns={{ base: 1, md: 2 }} gap="3">
						{CAP_FIELDS.map((field) => (
							<Field.Root key={field}>
								<Field.Label fontSize="sm">{CAP_LABELS[field]}</Field.Label>
								<Input
									size="sm"
									fontFamily="mono"
									inputMode="numeric"
									value={chain[field]}
									onChange={(event) =>
										setChain(index, { ...chain, [field]: event.target.value })
									}
									placeholder="default"
								/>
							</Field.Root>
						))}
						{LIST_FIELDS.map((field) => (
							<Field.Root key={field}>
								<Field.Label fontSize="sm">{LIST_LABELS[field]}</Field.Label>
								<NativeSelect.Root size="sm">
									<NativeSelect.Field
										aria-label={`${LIST_LABELS[field]} on chain ${chain.chainId}`}
										value={chain[field].mode}
										onChange={(event) =>
											setChain(index, {
												...chain,
												[field]: {
													...chain[field],
													mode: event.currentTarget.value as ListMode,
												},
											})
										}
									>
										<option value="default">Deployment default</option>
										<option value="any">Any address</option>
										<option value="only">Only these</option>
									</NativeSelect.Field>
									<NativeSelect.Indicator />
								</NativeSelect.Root>
								{chain[field].mode === "only" && (
									<Textarea
										mt="2"
										size="sm"
										rows={3}
										fontFamily="mono"
										placeholder="0x…, one per line"
										value={chain[field].text}
										onChange={(event) =>
											setChain(index, {
												...chain,
												[field]: { mode: "only", text: event.target.value },
											})
										}
									/>
								)}
							</Field.Root>
						))}
					</SimpleGrid>
				</Box>
			))}
			<Box>
				<Button
					size="xs"
					variant="outline"
					onClick={() =>
						onChange({
							...value,
							perChain: [
								...value.perChain,
								emptyChain(unused ? String(unused) : ""),
							],
						})
					}
				>
					<LuPlus /> Add a chain
				</Button>
			</Box>
			{[...policyProblems(value), ...(error ? [error] : [])].map((problem) => (
				<Text key={problem} color="red.fg" fontSize="sm">
					{problem}
				</Text>
			))}
		</Stack>
	);
}

/** The policy as stored, read-only, in the words the editor uses. */
export function PolicyView({ policy }: { policy: Record<string, unknown> }) {
	const perChain = (policy.perChain ?? {}) as Record<
		string,
		Record<string, unknown>
	>;
	const caps = CAP_FIELDS.filter((field) => policy[field] !== undefined);
	if (
		caps.length === 0 &&
		policy.relayRateLimitPerMinute === undefined &&
		Object.keys(perChain).length === 0
	)
		return (
			<Text fontSize="sm">The deployment defaults, with no overrides.</Text>
		);

	return (
		<Stack gap="2">
			<DataList.Root orientation="horizontal" size="sm">
				{caps.map((field) => (
					<Entry
						key={field}
						label={CAP_LABELS[field]}
						value={String(policy[field])}
					/>
				))}
				{policy.relayRateLimitPerMinute !== undefined && (
					<Entry
						label="Relay rate limit"
						value={`${String(policy.relayRateLimitPerMinute)} per minute`}
					/>
				)}
			</DataList.Root>
			{Object.entries(perChain).map(([chainId, entry]) => (
				<Box key={chainId} borderWidth="1px" rounded="md" p="2">
					<Text fontSize="xs" fontWeight="medium" mb="1">
						Chain {chainId}
					</Text>
					<DataList.Root orientation="horizontal" size="sm">
						{CAP_FIELDS.filter((field) => entry[field] !== undefined).map(
							(field) => (
								<Entry
									key={field}
									label={CAP_LABELS[field]}
									value={String(entry[field])}
								/>
							),
						)}
						{LIST_FIELDS.filter((field) => Array.isArray(entry[field])).map(
							(field) => {
								const list = entry[field] as string[];
								return (
									<Entry
										key={field}
										label={LIST_LABELS[field]}
										value={list.length === 0 ? "any address" : list.join("\n")}
									/>
								);
							},
						)}
					</DataList.Root>
				</Box>
			))}
		</Stack>
	);
}

function Entry({ label, value }: { label: string; value: string }) {
	return (
		<DataList.Item>
			<DataList.ItemLabel minW="44">{label}</DataList.ItemLabel>
			<DataList.ItemValue
				fontFamily="mono"
				fontSize="xs"
				whiteSpace="pre-wrap"
				wordBreak="break-all"
			>
				{value}
			</DataList.ItemValue>
		</DataList.Item>
	);
}
