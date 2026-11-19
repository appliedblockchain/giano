import { Box, Button, HStack, Input, Stack, Text } from "@chakra-ui/react";
import { type ReactNode, useEffect, useMemo, useState } from "react";
import { LuEye, LuEyeOff, LuPlus, LuSend } from "react-icons/lu";
import {
	createPublicClient,
	encodeFunctionData,
	getAddress,
	isAddress,
} from "viem";
import { erc20Abi, testErc20Abi } from "../lib/erc20";
import type { ErrorRecord } from "../lib/errors";
import {
	type Address,
	formatTime,
	formatToken,
	type Hex,
	shortHex,
} from "../lib/format";
import {
	findLatestTransfer,
	isBalanceRefusal,
	otherAccount,
	parseAmount,
	readerKey,
	redactionOf,
	refusalReason,
	staleReaderKeys,
} from "../lib/private-token";
import type { RunOutcome } from "../lib/run";
import { submitTransaction } from "../lib/run";
import {
	DELEGATE_RENEW_MARGIN_MS,
	type DelegateTicket,
	SignedReader,
} from "../lib/signed-reads";
import {
	type Demo,
	useDemo,
	useSectionEntries,
	useSettledCount,
} from "../state/store";
import {
	KeyValues,
	Mono,
	Outcomes,
	SectionCard,
	StatusText,
	type Tone,
} from "./primitives";
import { Field } from "./ui/field";

type Meta = { name: string; symbol: string; decimals: number };

/** An outsider's balance read is expected to fail with the token's refusal, and with nothing else. */
const refusedRead = (error: ErrorRecord) => isBalanceRefusal(error.message);

/** The ledger note on a send that is not followed by a balance read, because no delegate is approved. */
const NO_AUTOMATIC_READ =
	'balance not read after this send: the read delegate needs approval, and the wallet opens its popup only from a click on "Read my balance (signed)"';
type OutsiderRow = {
	label: string;
	tone: Tone;
	outcome: string;
	detail?: ReactNode;
};

/**
 * One signed reader per chain and connected wallet. It outlives a chain switch, so returning to a
 * chain asks for no new approval. PrivateTokenCard drops it when that chain's session ends or changes
 * account, whichever chain is selected.
 */
const readers = new Map<string, SignedReader>();

/**
 * The private token section (silent-data-network, design D6): a token whose balance only the holder
 * can read, on a chain whose RPC enforces that. Shown only for a chain whose configuration names
 * `privateToken`.
 */
export function PrivateTokenCard() {
	const { selected, state, account } = useDemo();
	// This card stays mounted across chain switches, so it watches every chain's session, not only the
	// selected one: a reader is dropped as soon as its session ends or changes account.
	useEffect(() => {
		for (const key of staleReaderKeys(
			readers.keys(),
			(chainId) => state.sessions[chainId]?.account,
		))
			readers.delete(key);
	}, [state.sessions]);
	const token = selected.config.privateToken;
	if (!token) return null;
	// Keyed by chain and account: a chain switch, a new session or another account starts the section
	// afresh, and a read or send still pending for the previous one cannot update the new one.
	return (
		<PrivateTokenSection
			key={`${selected.chainId}:${account ?? ""}`}
			token={token}
		/>
	);
}

function PrivateTokenSection({ token }: { token: Address }) {
	const demo = useDemo();
	const { registry, selected, account, run, isChainDisabled, state } = demo;
	const chainId = selected.chainId;
	const entry = registry.require(chainId);
	const entries = useSectionEntries("private-token");
	const settled = useSettledCount();

	const [meta, setMeta] = useState<Meta | null>();
	const [deployed, setDeployed] = useState<boolean>();
	const [balance, setBalance] = useState<bigint>();
	const [amount, setAmount] = useState("100");
	const [recipient, setRecipient] = useState("");
	const [busy, setBusy] = useState(false);
	const [outsider, setOutsider] = useState<OutsiderRow[]>();
	// A send succeeded, but the balance was not read after it: see `send`.
	const [unread, setUnread] = useState(false);

	// Name, symbol and decimals are public: read them unsigned.
	useEffect(() => {
		let live = true;
		Promise.all([
			entry.publicClient.readContract({
				address: token,
				abi: erc20Abi,
				functionName: "name",
			}),
			entry.publicClient.readContract({
				address: token,
				abi: erc20Abi,
				functionName: "symbol",
			}),
			entry.publicClient.readContract({
				address: token,
				abi: erc20Abi,
				functionName: "decimals",
			}),
		])
			.then(([name, symbol, decimals]) => {
				if (live) setMeta({ name, symbol, decimals });
			})
			.catch(() => {
				if (live) setMeta(null);
			});
		return () => {
			live = false;
		};
	}, [entry, token]);

	// The RPC checks a signed read against the wallet's code (ERC-1271), so a counterfactual wallet cannot read.
	// biome-ignore lint/correctness/useExhaustiveDependencies: `settled` is a trigger: another card can deploy the wallet, so check again after every operation settles
	useEffect(() => {
		if (!account) {
			setDeployed(undefined);
			return;
		}
		// A deployed wallet stays deployed. Setting it cancels a check still running.
		if (deployed === true) return;
		let live = true;
		entry.publicClient
			.getCode({ address: account })
			.then((code) => {
				if (live) setDeployed(Boolean(code && code !== "0x"));
			})
			.catch(() => {
				if (live) setDeployed(undefined);
			});
		return () => {
			live = false;
		};
	}, [entry, account, settled, deployed]);

	const latestTransfer = useMemo(
		() => findLatestTransfer(state.ledger.entries, chainId, account),
		[state.ledger.entries, chainId, account],
	);

	const reader = account ? readerFor(run, chainId, account) : undefined;
	// Render again when the delegate stops being valid, so the card does not show it as approved.
	const [, setExpired] = useState(0);
	// Read once: the getter checks the clock, so a second read can return undefined.
	const approved = reader?.delegate;
	const validUntil = approved
		? approved.expiresAt - DELEGATE_RENEW_MARGIN_MS
		: undefined;
	useEffect(() => {
		if (validUntil === undefined) return;
		const timer = setTimeout(
			() => setExpired((n) => n + 1),
			Math.max(0, validUntil - Date.now()),
		);
		return () => clearTimeout(timer);
	}, [validUntil]);

	if (!account || !reader) {
		return (
			<Frame entries={entries}>
				<StatusText tone="gray">
					Connect on {selected.config.name} to read your private balance.
				</StatusText>
			</Frame>
		);
	}
	const wallet = account;
	const signedClient = () =>
		createPublicClient({
			chain: entry.chain,
			transport: reader.transport(entry.chain.rpcUrls.default.http[0]),
		});
	const format = (value: bigint) =>
		meta ? formatToken(value, meta.decimals, meta.symbol) : value.toString();

	const readBalance = async (why?: string) => {
		const before = balance;
		const outcome = await run(
			{
				section: "private-token",
				label: "Signed balance read",
				method: "eth_call balanceOf, signed for the wallet",
				params: { token, account: wallet },
				chainId,
				account: wallet,
				noBalances: true,
			},
			async (api) => {
				// Approve the delegate before the request starts: the request runs under viem's timeout,
				// and a passkey prompt can take longer than that.
				await reader.approved();
				const value = await signedClient().readContract({
					address: token,
					abi: erc20Abi,
					functionName: "balanceOf",
					args: [wallet],
					account: wallet,
				});
				const change =
					before === undefined
						? ""
						: `; change since the previous read: ${value >= before ? "+" : ""}${format(value - before)}`;
				api.update({
					note: `reader ${wallet}, signed by delegate ${reader.delegate?.ticket.ephemeralAddress}${change}${why ? `; ${why}` : ""}`,
				});
				return { reader: wallet, balance: value.toString() };
			},
		);
		if (outcome.result) {
			setBalance(BigInt(outcome.result.balance));
			setUnread(false);
		}
	};

	/** The button's read. It holds `busy`, so no other wallet request starts while its approval is open. */
	const readOnClick = async () => {
		setBusy(true);
		try {
			await readBalance();
		} finally {
			setBusy(false);
		}
	};

	const send = async (op: "mint" | "transfer") => {
		if (!meta) return;
		let units: bigint;
		try {
			units = parseAmount(amount, meta.decimals);
		} catch {
			await refuse(`${op} (invalid amount)`, {
				amount,
				decimals: meta.decimals,
			});
			return;
		}
		if (op === "transfer" && !isAddress(recipient)) {
			await refuse("transfer (invalid recipient)", { recipient });
			return;
		}
		const data = (
			op === "mint"
				? encodeFunctionData({
						abi: testErc20Abi,
						functionName: "mint",
						args: [units],
					})
				: encodeFunctionData({
						abi: erc20Abi,
						functionName: "transfer",
						args: [getAddress(recipient), units],
					})
		) as Hex;
		setBusy(true);
		try {
			const outcome = await run(
				{
					section: "private-token",
					label:
						op === "mint"
							? `Mint ${amount} ${meta.symbol}`
							: `Transfer ${amount} ${meta.symbol} → ${shortHex(recipient)}`,
					method: "eth_sendTransaction",
					params: [{ to: token, data }],
					chainId,
					account: wallet,
					declaredPayer: "sponsored",
					sponsoredSend: true,
				},
				async (api) => {
					const receipt = await submitTransaction(api, { to: token, data });
					if (receipt.success !== false && !reader.delegate)
						api.update({ note: NO_AUTOMATIC_READ });
					return receipt;
				},
			);
			if (outcome.error || !outcome.result) return;
			// The operation was included, so the wallet is deployed: the EntryPoint deploys it (ERC-4337
			// initCode) before it runs the call, even when the call reverts. The first mint deploys it.
			setDeployed(true);
			if (outcome.result.success === false) return;
			// Read again only with an approved delegate. Otherwise the read would open the wallet's
			// approval popup long after the click, and the browser would block it (POPUP_BLOCKED).
			if (reader.delegate)
				await readBalance(
					`after ${op === "mint" ? "minting" : "transferring"} ${amount} ${meta.symbol}`,
				);
			else setUnread(true);
		} finally {
			setBusy(false);
		}
	};

	const refuse = (label: string, params: unknown) =>
		run(
			{
				section: "private-token",
				label,
				method: "eth_sendTransaction",
				params,
				chainId,
				account: wallet,
				noBalances: true,
			},
			async () => {
				throw new Error(`${label}: ${JSON.stringify(params)}`);
			},
		);

	/**
	 * An outsider's balance read must be refused. A returned balance is a privacy violation. Only the
	 * token's own refusal counts as refused: any other error leaves the question open.
	 */
	const judgeBalanceRead = (
		label: string,
		target: Address,
		outcome: RunOutcome<bigint>,
	): OutsiderRow => {
		if (outcome.error) {
			const refused = isBalanceRefusal(outcome.error.message);
			return {
				label,
				tone: refused ? "green" : "orange",
				outcome: refused ? "refused" : "read failed",
				detail: <Mono muted>{refusalReason(outcome.error.message)}</Mono>,
			};
		}
		const value = outcome.result ?? 0n;
		demo.recordViolation(
			"private-token",
			"A private balance was readable by an outsider",
			`${label}: ${selected.config.name} (chain ${chainId}), token ${token}, account ${target} returned ${value}`,
			chainId,
		);
		return { label, tone: "red", outcome: `returned ${format(value)}` };
	};

	const showOutsider = async () => {
		setBusy(true);
		try {
			// The signed read goes first: it may ask the wallet to approve the read delegate, and the
			// wallet opens its popup only right after the click. An unsigned read first would delay it.
			const other = otherAccount(wallet, latestTransfer?.recipient);
			const otherLabel = `Balance of ${shortHex(other)}, signed for your wallet`;
			const signedRow = judgeBalanceRead(
				otherLabel,
				other,
				await run(
					{
						section: "private-token",
						label: `Outsider: ${otherLabel.toLowerCase()}`,
						method: "eth_call balanceOf, signed for the wallet",
						params: { token, account: other },
						chainId,
						account: wallet,
						noBalances: true,
						expected: true,
						expectedError: refusedRead,
					},
					async () => {
						// Approve first, outside viem's request timeout: see readBalance.
						await reader.approved();
						return signedClient().readContract({
							address: token,
							abi: erc20Abi,
							functionName: "balanceOf",
							args: [other],
							account: wallet,
						});
					},
				),
			);

			const unsignedLabel = "Your balance, read without a signature";
			const unsignedRow = judgeBalanceRead(
				unsignedLabel,
				wallet,
				await run(
					{
						section: "private-token",
						label: `Outsider: ${unsignedLabel.toLowerCase()}`,
						method: "eth_call balanceOf, unsigned",
						params: { token, account: wallet },
						chainId,
						account: wallet,
						noBalances: true,
						expected: true,
						expectedError: refusedRead,
					},
					(api) =>
						api.entry.publicClient.readContract({
							address: token,
							abi: erc20Abi,
							functionName: "balanceOf",
							args: [wallet],
						}),
				),
			);
			const rows: OutsiderRow[] = [unsignedRow, signedRow];

			const txLabel = "Your latest transfer's bundle transaction, unsigned";
			if (!latestTransfer) {
				rows.push({
					label: txLabel,
					tone: "gray",
					outcome: "no transfer yet",
					detail: "Transfer first: this row reads that transfer's bundle.",
				});
			} else {
				const outcome = await run(
					{
						section: "private-token",
						label: `Outsider: ${txLabel.toLowerCase()}`,
						method: "eth_getTransactionByHash, unsigned",
						params: [latestTransfer.txHash],
						chainId,
						noBalances: true,
					},
					async (api) => {
						const tx = await api.entry.publicClient.request({
							method: "eth_getTransactionByHash",
							params: [latestTransfer.txHash],
						});
						// No transaction is not a redacted one: report the read as failed.
						if (!tx)
							throw new Error(
								`the RPC returned no transaction for ${latestTransfer.txHash}`,
							);
						api.update({
							note: redactionOf(tx).hidden
								? "the calldata and the sender came back as placeholders"
								: "the RPC returned the real calldata or sender",
						});
						return tx;
					},
				);
				const tx = outcome.result;
				const redaction = redactionOf(tx);
				rows.push({
					label: txLabel,
					tone: outcome.error ? "orange" : redaction.hidden ? "green" : "red",
					outcome: outcome.error
						? "read failed"
						: redaction.hidden
							? "hidden"
							: "visible",
					detail: outcome.error ? (
						<Mono muted>{refusalReason(outcome.error.message)}</Mono>
					) : (
						<KeyValues
							items={[
								["hash", latestTransfer.txHash],
								[
									"calldata (input)",
									`${tx?.input ?? "—"}${redaction.calldataHidden ? "  (placeholder)" : ""}`,
								],
								[
									"sender (from)",
									`${tx?.from ?? "—"}${redaction.senderHidden ? "  (placeholder)" : ""}`,
								],
								["to", tx?.to ?? "—"],
								["value", tx?.value ?? "—"],
							]}
						/>
					),
				});
			}
			setOutsider(rows);
		} finally {
			setBusy(false);
		}
	};

	const chainDisabled = isChainDisabled(chainId);
	const canRead = deployed === true && !busy && !chainDisabled && !!meta;
	const delegate = reader.delegate;

	return (
		<Frame entries={entries}>
			<KeyValues
				items={[
					[
						"Token",
						meta
							? `${meta.name} · ${meta.symbol} · ${token}`
							: meta === null
								? `${token} (cannot read name and symbol)`
								: token,
					],
					["Your balance", balance === undefined ? "—" : format(balance)],
					[
						"Read delegate",
						delegate
							? `${delegate.ticket.ephemeralAddress}, approved until ${formatTime(delegate.ticket.expires)}`
							: "none approved: the next signed read asks your wallet once (one passkey prompt), for 1 hour",
					],
				]}
			/>
			{unread && (
				<StatusText tone="gray">
					Your balance changed. Click "Read my balance (signed)" to read it: the
					read asks your wallet to approve the read delegate, and the wallet
					opens its popup only from a click.
				</StatusText>
			)}
			{deployed === false && (
				<StatusText tone="orange">
					Deploy the wallet first. The RPC checks a signed read against the
					wallet's code, and this wallet is not deployed yet. Your first mint
					deploys it.
				</StatusText>
			)}
			<HStack gap="3" align="flex-end" flexWrap="wrap">
				<Field label={`Amount${meta ? ` (${meta.symbol})` : ""}`} w="32">
					<Input
						fontFamily="mono"
						value={amount}
						onChange={(event) => setAmount(event.target.value)}
					/>
				</Field>
				<Button
					colorPalette="brand"
					onClick={() => void send("mint")}
					disabled={!meta || busy || chainDisabled}
					data-testid="private-mint"
				>
					<LuPlus /> Mint to self
				</Button>
				<Field label="Recipient" flex="1" minW="64">
					<Input
						fontFamily="mono"
						value={recipient}
						placeholder="0x…"
						onChange={(event) => setRecipient(event.target.value)}
					/>
				</Field>
				<Button
					colorPalette="brand"
					onClick={() => void send("transfer")}
					disabled={!meta || busy || chainDisabled || deployed !== true}
					data-testid="private-transfer"
				>
					<LuSend /> Transfer
				</Button>
			</HStack>
			<HStack gap="3" flexWrap="wrap">
				<Button
					variant="outline"
					onClick={() => void readOnClick()}
					disabled={!canRead}
					data-testid="private-read"
				>
					<LuEye /> Read my balance (signed)
				</Button>
				<Button
					variant="outline"
					onClick={() => void showOutsider()}
					disabled={!canRead}
					data-testid="private-outsider"
				>
					<LuEyeOff /> Show what an outsider sees
				</Button>
			</HStack>
			{outsider && (
				<Stack gap="3" data-testid="private-outsider-view">
					<Text fontSize="sm" fontWeight="medium">
						What an outsider sees
					</Text>
					{outsider.map((row) => (
						<Box key={row.label} borderWidth="1px" rounded="l2" p="3">
							<HStack justify="space-between" gap="3" flexWrap="wrap">
								<Text fontSize="sm">{row.label}</Text>
								<StatusText tone={row.tone}>{row.outcome}</StatusText>
							</HStack>
							{row.detail && <Box mt="2">{row.detail}</Box>}
						</Box>
					))}
				</Stack>
			)}
		</Frame>
	);
}

function Frame({
	entries,
	children,
}: {
	entries: ReturnType<typeof useSectionEntries>;
	children: ReactNode;
}) {
	return (
		<SectionCard
			id="private-token"
			title="Private token"
			description="Only the holder can read this token's balance: the chain's RPC refuses everyone else. The demo reads your balance with a request signed for your wallet, through a delegate key that your wallet approves once an hour."
			sdk={[
				[
					"personal_sign",
					"approves the read delegate: one passkey prompt per hour",
				],
				[
					"signed eth_call",
					"balanceOf with the wallet and delegate headers (src/lib/signed-reads.ts)",
				],
				["eth_sendTransaction", "mint / transfer, sponsored by the app"],
				[
					"publicClient (unsigned)",
					"the outsider view: the same reads with no signature",
				],
			]}
		>
			{children}
			<Outcomes entries={entries} />
		</SectionCard>
	);
}

/**
 * The reader for this chain and wallet, created on first use. Its one prompt goes through `run`, so
 * the ledger records it. It keeps only `run`, not the render's whole context, which holds the ledger.
 */
function readerFor(
	run: Demo["run"],
	chainId: number,
	wallet: Address,
): SignedReader {
	const key = readerKey(chainId, wallet);
	let reader = readers.get(key);
	if (!reader) {
		reader = new SignedReader({
			chainId,
			wallet,
			personalSign: (message, context) =>
				approveDelegate(run, chainId, wallet, message, context),
		});
		readers.set(key, reader);
	}
	return reader;
}

/**
 * Asks the wallet to approve the read delegate. A failure rethrows the wallet's own error, so the read
 * that needed the approval records the same type and code: a timeout stays `timed-out`.
 */
async function approveDelegate(
	run: Demo["run"],
	chainId: number,
	wallet: Address,
	message: Hex,
	{ ticket, renewed }: { ticket: DelegateTicket; renewed: boolean },
): Promise<Hex> {
	let failure: unknown;
	const outcome = await run(
		{
			section: "private-token",
			label: renewed
				? "Renew the read delegate (the previous one expired)"
				: "Approve the read delegate",
			method: "personal_sign",
			params: [message, wallet],
			chainId,
			account: wallet,
			noBalances: true,
		},
		async (api) => {
			const signature = await api.provider
				.request<Hex>({
					method: "personal_sign",
					params: [message, wallet],
				})
				.catch((error: unknown) => {
					failure = error;
					throw error;
				});
			api.update({
				note: `delegate ${ticket.ephemeralAddress} may sign reads for ${wallet} until ${ticket.expires}`,
			});
			return signature;
		},
	);
	if (!outcome.result)
		throw (
			failure ??
			new Error(
				outcome.error?.message ??
					"the wallet did not approve the read delegate",
			)
		);
	return outcome.result;
}
