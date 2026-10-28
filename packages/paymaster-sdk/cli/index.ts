#!/usr/bin/env node
/// <reference types="node" />
/**
 * giano-paymaster — a management CLI for the Giano sponsorship paymaster.
 *
 * Every command is a thin wrapper over `GianoPaymasterClient`, so the CLI and any other client
 * behave identically: same reads, same preflight simulation, same translated refusals.
 *
 * Signing is by raw EOA private key, which is a development affordance and is treated as one. A
 * key on the command line lands in shell history and in the process table, so outside a local
 * devnet the CLI warns before it signs, and every state-changing command asks for confirmation
 * unless `--yes` is passed.
 *
 * Production role holders for the timelocked functions (G9: fees, withdrawal addresses, role
 * changes, upgrades) are a timelock whose proposer is a Safe, and neither is driven by a key here.
 * With `--timelock <address>` those commands send nothing: they print the timelock proposal — its
 * operation id, the delay the timelock demands, when it would be ready, and the schedule / execute /
 * cancel calldata — and with `--safe-json <file>` write the Safe Transaction Builder batch that
 * schedules it. `timelock status`, `timelock pending` and `timelock execute <id>` read the delays,
 * list operations with their ETA, and execute a ready one where executors are open.
 *
 * Usage:
 *   giano-paymaster <command> [args] [flags]
 *   pnpm --filter @appliedblockchain/giano-paymaster-sdk cli -- <command> [args] [flags]
 *
 * Global flags (each with an env fallback):
 *   --rpc <url>           RPC_URL, default http://localhost:8545
 *   --paymaster <0x..>    SPONSORSHIP_PAYMASTER_ADDRESS, else the contracts registry for the chain
 *   --private-key <0x..>  PAYMASTER_PRIVATE_KEY / DEPLOYER_PRIVATE_KEY, else anvil key 0 on 31337
 *   --timelock <0x..>     GIANO_PAYMASTER_TIMELOCK; timelocked commands propose instead of sending
 *   --json                machine-readable output (implies --yes for reads)
 *   --yes                 skip the confirmation prompt on state-changing commands
 *
 * Run `giano-paymaster help` for the command list.
 */
import { writeFileSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import {
	type Address,
	type Chain,
	createPublicClient,
	createWalletClient,
	defineChain,
	formatEther,
	type Hex,
	http,
	parseEther,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
	formatDuration,
	GianoPaymasterClient,
	type GianoTimelockClient,
	MissingRoleError,
	PAYMASTER_ROLE_NAMES,
	type PaymasterRoleName,
	PaymasterSdkError,
	type ProposeOptions,
	parseDuration,
	ROLE_DESCRIPTIONS,
	type SponsorshipRecord,
	TIMELOCKED_OPERATIONS,
	type TimelockedFunctionName,
	type TimelockOperation,
	type TimelockProposalDraft,
	toTenantId,
	type WriteResult,
} from "../src/index";

/** Anvil's first account. Deterministic, funded, and never used anywhere real. */
const ANVIL_KEY =
	"0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

// --- output --------------------------------------------------------------------------------

let jsonMode = false;

const out = (message = ""): void => {
	if (jsonMode) return;
	console.log(message);
};

const emit = (value: unknown): void => {
	if (!jsonMode) return;
	console.log(
		JSON.stringify(
			value,
			(_key, item) => (typeof item === "bigint" ? item.toString() : item),
			2,
		),
	);
};

const ok = (message: string): void => out(`  \x1b[32m✓\x1b[0m ${message}`);
const warn = (message: string): void => out(`  \x1b[33m⚠\x1b[0m ${message}`);
const bad = (message: string): void => out(`  \x1b[31m✗\x1b[0m ${message}`);
const bullet = (message: string): void => out(`  • ${message}`);
const heading = (title: string): void => {
	out();
	out(`\x1b[1m${title}\x1b[0m`);
};

const eth = (wei: bigint): string => `${formatEther(wei)} ETH`;
const pad = (value: string, width: number): string => value.padEnd(width);

// --- argument parsing ------------------------------------------------------------------------

type Args = {
	positional: string[];
	flags: Record<string, string>;
};

function parseArgs(argv: string[]): Args {
	const positional: string[] = [];
	const flags: Record<string, string> = {};

	for (let i = 0; i < argv.length; i++) {
		const token = argv[i];
		if (!token.startsWith("--")) {
			positional.push(token);
			continue;
		}
		const next = argv[i + 1];
		flags[token.slice(2)] =
			next && !next.startsWith("--") ? (i++, next) : "true";
	}
	return { positional, flags };
}

// --- confirmation ------------------------------------------------------------------------------

/**
 * Confirms a state-changing command.
 *
 * Deliberately not skippable by a flag alone on a non-local chain without the operator seeing what
 * they are about to do: the prompt prints the chain, the paymaster and the signing account, which
 * is exactly the set of things people get wrong when they have several terminals open.
 */
async function confirm(context: Context, action: string): Promise<boolean> {
	if (context.assumeYes) return true;
	if (!process.stdin.isTTY) {
		throw new PaymasterSdkError(
			`refusing to ${action} without a terminal to confirm at. Pass --yes if this is scripted.`,
		);
	}

	const rl = createInterface({ input: process.stdin, output: process.stdout });
	try {
		out();
		out(`  About to ${action}`);
		out(
			`    chain     ${context.chainId}${context.isLocal ? " (local devnet)" : ""}`,
		);
		out(`    paymaster ${context.paymaster.address}`);
		if (context.timelock) out(`    timelock  ${context.timelock.address}`);
		out(`    signer    ${context.account}`);
		const answer = await rl.question("  Proceed? [y/N] ");
		return (
			answer.trim().toLowerCase() === "y" ||
			answer.trim().toLowerCase() === "yes"
		);
	} finally {
		rl.close();
	}
}

/** Runs a write, printing the hash as soon as it exists and then waiting for the receipt. */
async function submit(
	context: Context,
	action: string,
	send: () => Promise<WriteResult>,
): Promise<void> {
	if (!(await confirm(context, action))) {
		out("  cancelled");
		return;
	}
	const result = await send();
	out(`  submitted ${result.hash}`);
	const receipt = await result.wait();
	ok(
		`${action} — confirmed in block ${receipt.blockNumber} (${receipt.status})`,
	);
	emit({
		action,
		hash: result.hash,
		blockNumber: receipt.blockNumber,
		status: receipt.status,
	});
}

/**
 * A positive whole number from a flag, or the default when it is absent.
 *
 * `Number(undefined)` is `NaN` and so is `Number('five')`, and both would slip past a plain
 * comparison — every `n >= NaN` is false, so a loop bounded by one would run until it hit a
 * different stop condition. Which for the log-paging loops here means walking toward genesis a
 * window at a time because someone mistyped a flag.
 */
function count(
	flag: string | undefined,
	fallback: number,
	name: string,
): number {
	if (flag === undefined) return fallback;
	const value = Number(flag);
	if (!Number.isSafeInteger(value) || value < 1)
		throw new PaymasterSdkError(
			`${name} must be a positive whole number, got "${flag}"`,
		);
	return value;
}

/**
 * One tenant's slug, hunted backwards a window at a time.
 *
 * A slug is emitted once, at registration, and log reads cover a window (see the SDK's
 * `getTenantSlugs`) — so the label for a tenant registered long ago is not in the window at the
 * head. Filtering on the indexed tenant id makes the hunt the node skipping windows rather than
 * this process downloading and discarding them, which is what makes paging back affordable.
 */
async function findSlug(
	paymaster: GianoPaymasterClient,
	tenantId: Hex,
	maxWindows: number,
): Promise<string | undefined> {
	let page = await paymaster.getTenantSlugs({ tenantId });

	for (let window = 1; window < maxWindows; window++) {
		const slug = page.slugs.get(tenantId);
		if (slug !== undefined || !page.older) return slug;
		page = await paymaster.getTenantSlugs({ tenantId, range: page.older });
	}
	return page.slugs.get(tenantId);
}

// --- commands ----------------------------------------------------------------------------------

type Context = {
	paymaster: GianoPaymasterClient;
	/** Set by `--timelock` / GIANO_PAYMASTER_TIMELOCK. Timelocked commands then propose, not send. */
	timelock?: GianoTimelockClient;
	/** The signer, or the zero address when no key was supplied (reads and proposals). */
	account: Address;
	chainId: number;
	isLocal: boolean;
	assumeYes: boolean;
	args: Args;
};

type Command = {
	usage: string;
	summary: string;
	/**
	 * True when the command sends a transaction; those require a signer and a confirmation. A
	 * function for a command whose subcommands differ (`timelock status` reads, `timelock execute`
	 * sends).
	 */
	writes?: boolean | ((args: Args) => boolean);
	/**
	 * True for commands that call a timelocked paymaster function (G9). With `--timelock` they send
	 * nothing and so need no key; they print the proposal instead.
	 */
	timelocked?: boolean;
	run: (context: Context) => Promise<void>;
};

// --- the timelock (G9) --------------------------------------------------------------------------

/** `--salt` and `--delay`, for reproducing or lengthening a proposal. */
function proposeOptions(context: Context): ProposeOptions {
	const { salt, delay } = context.args.flags;
	if (salt !== undefined && !/^0x[0-9a-fA-F]{64}$/.test(salt))
		throw new PaymasterSdkError(
			"--salt must be a 0x-prefixed 32-byte hex value",
		);
	return {
		salt: salt as Hex | undefined,
		delay: delay === undefined ? undefined : BigInt(parseDuration(delay)),
	};
}

const when = (unixSeconds: number): string => {
	const seconds = unixSeconds - Math.floor(Date.now() / 1000);
	const at = new Date(unixSeconds * 1000).toISOString();
	if (seconds <= 0) return `${at} (passed)`;
	return `${at} (in ${formatDuration(seconds > 3600 ? Math.ceil(seconds / 60) * 60 : seconds)})`;
};

/**
 * Prints a timelock proposal and, with `--safe-json`, writes the Safe batch that schedules it.
 *
 * Sends nothing. The proposer is a Safe in production (R3), and a key in this process would be the
 * wrong signer for it even where it happens to hold PROPOSER_ROLE.
 */
async function printProposal(
	context: Context,
	build: (timelock: GianoTimelockClient) => Promise<TimelockProposalDraft>,
): Promise<void> {
	const timelock = context.timelock;
	if (!timelock) throw new PaymasterSdkError("no --timelock given");
	const proposal = await build(timelock);
	const batch = timelock.safeBatch(proposal, "schedule");
	const file = context.args.flags["safe-json"];
	if (file && file !== "true") {
		writeFileSync(file, `${JSON.stringify(batch, null, 2)}\n`);
	}
	emit({ ...proposal, safeBatch: batch, safeJson: file });

	heading(`Timelock proposal ${proposal.id}`);
	bullet(`what       ${proposal.summary}`);
	bullet(`timelock   ${proposal.timelock} (chain ${proposal.chainId})`);
	bullet(
		`delay      ${formatDuration(proposal.delay)}${proposal.delay > proposal.requiredDelay ? ` (the timelock requires ${formatDuration(proposal.requiredDelay)})` : ""}`,
	);
	bullet(`ready      ${when(proposal.readyAtIfScheduledNow)} if scheduled now`);
	bullet(`salt       ${proposal.salt}`);
	out();
	out(`  1. A proposer (the Safe) sends to ${proposal.timelock}:`);
	out(`     ${proposal.schedule}`);
	out(`  2. Once ready, an executor sends to ${proposal.timelock}:`);
	out(`     ${proposal.execute}`);
	out(
		"     (or run `giano-paymaster timelock execute <id>` where executors are open)",
	);
	out("  To cancel while it is pending, a canceller sends:");
	out(`     ${proposal.cancel}`);
	out();
	if (file && file !== "true")
		ok(`Safe Transaction Builder batch (schedule) written to ${file}`);
	else bullet("pass --safe-json <file> for the Safe Transaction Builder batch");
	bullet("nothing was sent");
}

/**
 * Runs a timelocked command: the proposal with `--timelock`, otherwise a direct send — which works
 * only where the signer still holds the role, as on a devnet.
 *
 * The role is checked before the confirmation prompt, so an operator on a handed-off deployment is
 * told to use `--timelock` straight away rather than after confirming a send that cannot succeed.
 */
async function timelocked(
	context: Context,
	functionName: TimelockedFunctionName,
	action: string,
	send: () => Promise<WriteResult>,
	propose: (
		timelock: GianoTimelockClient,
		options: ProposeOptions,
	) => Promise<TimelockProposalDraft>,
): Promise<void> {
	if (context.timelock)
		return printProposal(context, (timelock) =>
			propose(timelock, proposeOptions(context)),
		);

	const role = TIMELOCKED_OPERATIONS[functionName].role;
	const hint = `${functionName} is timelocked (${role}): pass --timelock <address> (or set GIANO_PAYMASTER_TIMELOCK) to print the proposal and Safe batch instead of sending.`;
	if (!(await context.paymaster.hasRole(role, context.account)))
		throw new PaymasterSdkError(
			`${context.account} does not hold ${role}, so it cannot ${action}. ${hint}`,
		);
	try {
		await submit(context, action, send);
	} catch (error) {
		if (error instanceof MissingRoleError && error.timelocked)
			throw new PaymasterSdkError(`${error.message}\n  ${hint}`, {
				cause: error,
			});
		throw error;
	}
}

const requireTimelock = (context: Context): GianoTimelockClient => {
	if (!context.timelock)
		throw new PaymasterSdkError(
			"this needs the timelock's address: pass --timelock <address> or set GIANO_PAYMASTER_TIMELOCK",
		);
	return context.timelock;
};

function printOperation(operation: TimelockOperation): void {
	// Ready is the contract's word, measured against the chain's clock — which on a devnet can run
	// ahead of this machine's, so a ready operation is not described as "in 50s".
	const eta =
		operation.state === "ready" && operation.readyAt !== undefined
			? `executable since ${new Date(operation.readyAt * 1000).toISOString()}`
			: operation.readyAt !== undefined
				? when(operation.readyAt)
				: operation.state === "done"
					? `executed in block ${operation.executedBlock ?? "?"}`
					: operation.state === "cancelled"
						? `cancelled in block ${operation.cancelledBlock ?? "?"}`
						: "—";
	out(`  ${operation.id}`);
	out(
		`    ${pad(operation.state, 10)}${eta}${operation.delay !== undefined ? `  (delay ${formatDuration(operation.delay)})` : ""}`,
	);
	for (const call of operation.calls)
		out(
			`    • ${call.decoded?.summary ?? `call ${call.target} with ${call.data.slice(0, 10)}…`}`,
		);
	if (!operation.complete)
		out(
			"    scheduled before the blocks read — raise --windows to see its full scheduling",
		);
}

const requireArg = (context: Context, index: number, name: string): string => {
	const value = context.args.positional[index];
	if (!value)
		throw new PaymasterSdkError(
			`missing <${name}>. See \`giano-paymaster help\`.`,
		);
	return value;
};

const requireAddress = (
	context: Context,
	index: number,
	name: string,
): Address => {
	const value = requireArg(context, index, name);
	if (!/^0x[0-9a-fA-F]{40}$/.test(value))
		throw new PaymasterSdkError(`<${name}> is not an address: ${value}`);
	return value as Address;
};

const requireEth = (context: Context, index: number, name: string): bigint => {
	const value = requireArg(context, index, name);
	try {
		return parseEther(value);
	} catch {
		throw new PaymasterSdkError(`<${name}> is not an amount in ETH: ${value}`);
	}
};

const commands: Record<string, Command> = {
	status: {
		usage: "status",
		summary: "configuration, stake, solvency and roster in one view",
		run: async ({ paymaster }) => {
			const overview = await paymaster.getOverview();
			emit(overview);

			heading(`Paymaster ${overview.address} (chain ${overview.chainId})`);
			bullet(`EntryPoint          ${overview.config.entryPoint}`);
			bullet(
				`accepting new work  ${overview.config.paused ? "NO — paused" : "yes"}`,
			);
			bullet(`default fee         ${eth(overview.config.defaultFeeWei)}`);
			bullet(`post-op allowance   ${overview.config.postOpGasAllowance} gas`);
			bullet(`penalty             ${overview.config.penaltyBps} bps`);

			heading("Funds");
			bullet(`deposit          ${eth(overview.solvency.depositWei)}`);
			bullet(
				`stake            ${eth(overview.stake.stakeWei)}${overview.stake.staked ? "" : "  (NOT STAKED)"}`,
			);
			bullet(`treasury         ${eth(overview.solvency.treasuryWei)}`);
			bullet(`tenant balances  ${eth(overview.solvency.tenantBalancesWei)}`);
			if (overview.solvency.holds)
				ok(
					`invariant holds — ${eth(overview.solvency.slackWei)} unattributed slack`,
				);
			else
				bad(
					`INVARIANT BREACHED — claims ${eth(overview.solvency.claimsWei)} exceed deposit ${eth(overview.solvency.depositWei)}`,
				);

			heading(`Tenants (${overview.tenants.length})`);
			for (const tenant of overview.tenants) {
				bullet(
					`${pad(tenant.slug ?? tenant.uuid, 24)} ${pad(tenant.status, 11)} ${eth(tenant.balance)}${tenant.deficit > 0n ? `  deficit ${eth(tenant.deficit)}` : ""}`,
				);
			}

			heading(`Signing keys (${overview.signers.length})`);
			for (const signer of overview.signers) bullet(signer);
			if (overview.signers.length === 0)
				warn("none — nothing can be sponsored");
		},
	},

	health: {
		usage: "health",
		summary: "run the deployment checks; exits non-zero on any failure",
		run: async ({ paymaster }) => {
			const report = await paymaster.getHealth();
			emit(report);

			heading("Health");
			for (const check of report.checks) {
				const line = `${check.label}: ${check.detail}`;
				if (check.level === "ok") ok(line);
				else if (check.level === "warn") warn(line);
				else bad(line);
				if (check.remedy) out(`      → ${check.remedy}`);
			}
			out();
			out(`  overall: ${report.level}`);
			if (report.level === "fail") process.exitCode = 1;
		},
	},

	tenants: {
		usage: "tenants",
		summary: "list every registered tenant",
		run: async ({ paymaster }) => {
			const tenants = await paymaster.listTenants({ withSlugs: true });
			emit(tenants);

			heading(`Tenants (${tenants.length})`);
			if (tenants.length === 0) {
				warn("none registered");
				return;
			}
			out(
				`  ${pad("SLUG", 22)}${pad("UUID", 38)}${pad("STATUS", 11)}${pad("BALANCE", 26)}DEFICIT`,
			);
			for (const tenant of tenants) {
				out(
					`  ${pad(tenant.slug ?? "—", 22)}${pad(tenant.uuid, 38)}${pad(tenant.status, 11)}${pad(eth(tenant.balance), 26)}${eth(tenant.deficit)}`,
				);
			}
		},
	},

	tenant: {
		usage: "tenant <id> [--windows <n>]",
		summary: "show one tenant in full",
		run: async ({ paymaster, args }) => {
			const id = args.positional[0];
			if (!id)
				throw new PaymasterSdkError(
					"missing <id>: a tenant UUID or 16-byte hex id",
				);
			const tenant = await paymaster.getTenant(id);
			const slug = await findSlug(
				paymaster,
				tenant.id,
				count(args.flags.windows, 5, "--windows"),
			);
			emit({ ...tenant, slug });

			heading(`Tenant ${slug ?? tenant.uuid}`);
			bullet(`uuid              ${tenant.uuid}`);
			bullet(`bytes16           ${tenant.id}`);
			bullet(`status            ${tenant.status}`);
			bullet(`balance           ${eth(tenant.balance)}`);
			bullet(`deficit           ${eth(tenant.deficit)}`);
			bullet(
				`fee               ${eth(tenant.effectiveFeeWei)}${tenant.hasFeeOverride ? " (override)" : " (deployment default)"}`,
			);
			bullet(`withdraws to      ${tenant.withdrawAddress}`);
			if (tenant.deficit > 0n)
				warn("in deficit — it cannot transact until funded");
		},
	},

	register: {
		usage: "register <tenant-id> <withdraw-address> <slug>",
		summary: "register a tenant (TENANT_ADMIN_ROLE)",
		writes: true,
		run: async (context) => {
			const id = requireArg(context, 0, "tenant-id");
			const withdrawAddress = requireAddress(context, 1, "withdraw-address");
			const slug = requireArg(context, 2, "slug");
			out(`  ${id} normalises to ${toTenantId(id)}`);
			await submit(context, `register tenant ${slug}`, () =>
				context.paymaster.registerTenant(id, withdrawAddress, slug),
			);
		},
	},

	fund: {
		usage: "fund <tenant-id> <eth>",
		summary: "fund a tenant (anyone may); clears any deficit first",
		writes: true,
		run: async (context) => {
			const id = requireArg(context, 0, "tenant-id");
			const amount = requireEth(context, 1, "eth");
			await submit(context, `fund ${id} with ${eth(amount)}`, () =>
				context.paymaster.depositFor(id, amount),
			);
		},
	},

	withdraw: {
		usage: "withdraw <tenant-id> <eth> <to>",
		summary:
			"withdraw a tenant balance (only that tenant's withdrawal address)",
		writes: true,
		run: async (context) => {
			const id = requireArg(context, 0, "tenant-id");
			const amount = requireEth(context, 1, "eth");
			const to = requireAddress(context, 2, "to");
			await submit(context, `withdraw ${eth(amount)} from ${id}`, () =>
				context.paymaster.withdrawTenant(id, amount, to),
			);
		},
	},

	enable: {
		usage: "enable <tenant-id>",
		summary: "allow a tenant to have work sponsored again (TENANT_ADMIN_ROLE)",
		writes: true,
		run: async (context) => {
			const id = requireArg(context, 0, "tenant-id");
			await submit(context, `enable ${id}`, () =>
				context.paymaster.setTenantEnabled(id, true),
			);
		},
	},

	disable: {
		usage: "disable <tenant-id>",
		summary:
			"stop sponsoring a tenant, without touching its balance (TENANT_ADMIN_ROLE)",
		writes: true,
		run: async (context) => {
			const id = requireArg(context, 0, "tenant-id");
			await submit(context, `disable ${id}`, () =>
				context.paymaster.setTenantEnabled(id, false),
			);
		},
	},

	"set-withdraw-address": {
		usage: "set-withdraw-address <tenant-id> <address>",
		summary: "move a tenant's exit (WITHDRAW_ADDRESS_ADMIN_ROLE, timelocked)",
		writes: true,
		timelocked: true,
		run: async (context) => {
			const id = requireArg(context, 0, "tenant-id");
			const address = requireAddress(context, 1, "address");
			await timelocked(
				context,
				"setTenantWithdrawAddress",
				`point ${id} at ${address}`,
				() => context.paymaster.setTenantWithdrawAddress(id, address),
				(timelock, options) =>
					timelock.proposeSetTenantWithdrawAddress(id, address, options),
			);
		},
	},

	"set-fee": {
		usage: "set-fee [<tenant-id>] <eth> | <tenant-id> --clear",
		summary:
			"set the default fee, or a per-tenant override (FEE_ADMIN_ROLE, timelocked)",
		writes: true,
		timelocked: true,
		run: async (context) => {
			const [first, second] = context.args.positional;
			if (!first)
				throw new PaymasterSdkError(
					"missing argument. See `giano-paymaster help`.",
				);

			// One positional means the deployment-wide default; two means a tenant override.
			if (!second && context.args.flags.clear !== "true") {
				const amount = requireEth(context, 0, "eth");
				await timelocked(
					context,
					"setDefaultFee",
					`set the default fee to ${eth(amount)}`,
					() => context.paymaster.setDefaultFee(amount),
					(timelock, options) => timelock.proposeSetDefaultFee(amount, options),
				);
				return;
			}
			if (context.args.flags.clear === "true") {
				await timelocked(
					context,
					"setTenantFee",
					`clear the fee override on ${first}`,
					() => context.paymaster.setTenantFee(first, false, 0n),
					(timelock, options) =>
						timelock.proposeSetTenantFee(first, false, 0n, options),
				);
				return;
			}
			const amount = requireEth(context, 1, "eth");
			await timelocked(
				context,
				"setTenantFee",
				`set ${first}'s fee to ${eth(amount)}`,
				() => context.paymaster.setTenantFee(first, true, amount),
				(timelock, options) =>
					timelock.proposeSetTenantFee(first, true, amount, options),
			);
		},
	},

	signers: {
		usage: "signers",
		summary: "list the authorised sponsorship signing keys",
		run: async ({ paymaster }) => {
			const signers = await paymaster.getSigners();
			emit(signers);
			heading(`Signing keys (${signers.length})`);
			for (const signer of signers) bullet(signer);
			if (signers.length === 0) warn("none — nothing can be authorised");
		},
	},

	"add-signer": {
		usage: "add-signer <address>",
		summary: "authorise a sponsorship signing key (SIGNER_ADMIN_ROLE)",
		writes: true,
		run: async (context) => {
			const signer = requireAddress(context, 0, "address");
			await submit(context, `authorise signer ${signer}`, () =>
				context.paymaster.addSigner(signer),
			);
		},
	},

	"remove-signer": {
		usage: "remove-signer <address>",
		summary:
			"revoke a sponsorship signing key, effective immediately (SIGNER_ADMIN_ROLE)",
		writes: true,
		run: async (context) => {
			const signer = requireAddress(context, 0, "address");
			await submit(context, `revoke signer ${signer}`, () =>
				context.paymaster.removeSigner(signer),
			);
		},
	},

	roles: {
		usage: "roles [address]",
		summary: "show role holders, or the roles one address holds",
		run: async ({ paymaster, args }) => {
			const subject = args.positional[0] as Address | undefined;
			if (subject) {
				const held = await paymaster.getRolesOf(subject);
				emit({ account: subject, roles: held });
				heading(`Roles held by ${subject}`);
				if (held.length === 0) warn("none");
				for (const role of held) {
					bullet(`${pad(role, 20)} may ${ROLE_DESCRIPTIONS[role].may}`);
				}
				return;
			}

			const roles = await paymaster.getRoleHolders();
			emit(roles);
			heading("Role holders");
			for (const entry of roles) {
				const holders =
					entry.holders.length > 0 ? entry.holders.join(", ") : "(nobody)";
				if (entry.name === "DEFAULT_ADMIN_ROLE") {
					if (entry.holders.length === 0)
						ok("DEFAULT_ADMIN_ROLE  (nobody) — there is no superuser");
					else
						bad(
							`DEFAULT_ADMIN_ROLE  ${holders} — a superuser by another name; revoke it`,
						);
					continue;
				}
				bullet(`${pad(entry.name, 20)}${holders}`);
			}
		},
	},

	grant: {
		usage: "grant <ROLE> <address>",
		summary: "grant a role (ROLE_ADMIN, timelocked)",
		writes: true,
		timelocked: true,
		run: async (context) => {
			const role = requireRole(requireArg(context, 0, "ROLE"));
			const account = requireAddress(context, 1, "address");
			await timelocked(
				context,
				"grantRole",
				`grant ${role} to ${account}`,
				() => context.paymaster.grantRole(role, account),
				(timelock, options) =>
					timelock.proposeGrantRole(role, account, options),
			);
		},
	},

	revoke: {
		usage: "revoke <ROLE> <address>",
		summary: "revoke a role (ROLE_ADMIN, timelocked)",
		writes: true,
		timelocked: true,
		run: async (context) => {
			const role = requireRole(requireArg(context, 0, "ROLE"));
			const account = requireAddress(context, 1, "address");
			await timelocked(
				context,
				"revokeRole",
				`revoke ${role} from ${account}`,
				() => context.paymaster.revokeRole(role, account),
				(timelock, options) =>
					timelock.proposeRevokeRole(role, account, options),
			);
		},
	},

	upgrade: {
		usage: "upgrade <implementation> [--call <0x..>] --timelock <0x..>",
		summary:
			"propose upgrading the paymaster (UPGRADER_ROLE, timelocked; proposal only)",
		timelocked: true,
		// Deploying the implementation and a key-held upgrade are the deploy CLI's job
		// (`deploy:cli upgrade`); this is only the proposal, so it sends nothing either way.
		run: async (context) => {
			const implementation = requireAddress(context, 0, "implementation");
			const call = context.args.flags.call;
			if (call !== undefined && !/^0x([0-9a-fA-F]{2})*$/.test(call))
				throw new PaymasterSdkError("--call must be 0x-prefixed calldata");
			requireTimelock(context);
			await printProposal(context, (timelock) =>
				timelock.proposeUpgrade(
					implementation,
					(call ?? "0x") as Hex,
					proposeOptions(context),
				),
			);
		},
	},

	timelock: {
		usage: "timelock status | pending [--all] [--windows <n>] | execute <id>",
		summary:
			"the timelock's delays, its operations with their ETA, or execute a ready one",
		writes: (args) => args.positional[0] === "execute",
		run: async (context) => {
			const timelock = requireTimelock(context);
			const [sub = "status", id] = context.args.positional;

			if (sub === "status") {
				const config = await timelock.getConfig();
				emit(config);
				heading(`Timelock ${config.address} (chain ${config.chainId})`);
				bullet(`paymaster        ${config.paymaster}`);
				bullet(`minimum delay    ${formatDuration(config.minDelay)}`);
				bullet(
					`executors        ${config.executorsOpen ? "open — anyone may execute a ready operation" : "restricted to EXECUTOR_ROLE holders"}`,
				);
				heading("Delays");
				for (const entry of config.functions) {
					bullet(
						`${pad(entry.functionName, 26)}${pad(formatDuration(entry.effectiveDelay), 8)}${pad(entry.role, 29)}${entry.functionDelay === 0n ? "(no delay of its own: the minimum)" : ""}`,
					);
				}
				heading("Roles held");
				for (const [role, held] of Object.entries(config.holdsRole)) {
					if (held) ok(`${role} held by the timelock`);
					else
						warn(
							`${role} NOT held by the timelock — its functions are still sent from a key`,
						);
				}
				return;
			}

			if (sub === "pending") {
				const windows = count(context.args.flags.windows, 5, "--windows");
				const all = context.args.flags.all === "true";
				const page = await timelock.getOperations({ windows });
				const shown = page.operations.filter(
					(operation) =>
						all || operation.state === "waiting" || operation.state === "ready",
				);
				emit({ ...page, operations: shown });
				heading(
					`Timelock operations in blocks ${page.fromBlock}–${page.toBlock} (${shown.length}${all ? "" : " pending"})`,
				);
				if (shown.length === 0)
					bullet(
						all
							? "none in these blocks"
							: "nothing waiting or ready — pass --all for done and cancelled ones",
					);
				for (const operation of shown) printOperation(operation);
				if (page.older)
					bullet(
						`operations scheduled before block ${page.fromBlock} are not shown — raise --windows to reach them`,
					);
				return;
			}

			if (sub === "execute") {
				if (!id || !/^0x[0-9a-fA-F]{64}$/.test(id))
					throw new PaymasterSdkError(
						"missing <id>: the operation id, as `timelock pending` prints it",
					);
				const windows = count(context.args.flags.windows, 5, "--windows");
				const operation = await timelock.findOperation(id as Hex, { windows });
				if (!operation)
					throw new PaymasterSdkError(
						`operation ${id} is not in the last ${windows} window(s) of blocks — raise --windows`,
					);
				printOperation(operation);
				await submit(context, `execute timelock operation ${id}`, () =>
					timelock.executeOperation(operation),
				);
				return;
			}

			throw new PaymasterSdkError(
				`unknown timelock command "${sub}": status, pending or execute`,
			);
		},
	},

	pause: {
		usage: "pause",
		summary:
			"stop accepting new sponsorships; withdrawals keep working (PAUSER_ROLE)",
		writes: true,
		run: async (context) =>
			submit(context, "pause the paymaster", () => context.paymaster.pause()),
	},

	unpause: {
		usage: "unpause",
		summary: "resume accepting sponsorships (PAUSER_ROLE)",
		writes: true,
		run: async (context) =>
			submit(context, "unpause the paymaster", () =>
				context.paymaster.unpause(),
			),
	},

	"set-post-op-gas": {
		usage: "set-post-op-gas <gas-units>",
		summary: "set the settlement gas allowance (PARAM_ADMIN_ROLE)",
		writes: true,
		run: async (context) => {
			const units = Number(requireArg(context, 0, "gas-units"));
			if (!Number.isInteger(units) || units < 0)
				throw new PaymasterSdkError(
					"<gas-units> must be a non-negative integer",
				);
			await submit(context, `set the post-op gas allowance to ${units}`, () =>
				context.paymaster.setPostOpGasAllowance(units),
			);
		},
	},

	"set-penalty-bps": {
		usage: "set-penalty-bps <bps>",
		summary:
			"set the penalty bound in basis points, max 5000 (PARAM_ADMIN_ROLE)",
		writes: true,
		run: async (context) => {
			const bps = Number(requireArg(context, 0, "bps"));
			if (!Number.isInteger(bps) || bps < 0 || bps > 5000)
				throw new PaymasterSdkError(
					"<bps> must be an integer between 0 and 5000",
				);
			await submit(context, `set the penalty to ${bps} bps`, () =>
				context.paymaster.setPenaltyBps(bps),
			);
		},
	},

	stake: {
		usage: "stake [<eth> <unstake-delay-seconds>]",
		summary: "show the stake, or add to it (STAKE_ADMIN_ROLE)",
		writes: true,
		run: async (context) => {
			if (context.args.positional.length === 0) {
				const info = await context.paymaster.getStakeInfo();
				emit(info);
				heading("Stake");
				bullet(`staked           ${info.staked}`);
				bullet(`amount           ${eth(info.stakeWei)}`);
				bullet(`unstake delay    ${info.unstakeDelaySec}s`);
				bullet(`deposit          ${eth(info.depositWei)}`);
				if (info.withdrawTime > 0)
					warn(`unlocking — withdrawable from unix time ${info.withdrawTime}`);
				if (!info.staked)
					warn("not staked — bundlers will reject this paymaster’s operations");
				return;
			}
			const amount = requireEth(context, 0, "eth");
			const delay = Number(requireArg(context, 1, "unstake-delay-seconds"));
			if (!Number.isInteger(delay) || delay <= 0)
				throw new PaymasterSdkError(
					"<unstake-delay-seconds> must be a positive integer",
				);
			await submit(
				context,
				`stake ${eth(amount)} with a ${delay}s unstake delay`,
				() => context.paymaster.addStake(amount, delay),
			);
		},
	},

	"unlock-stake": {
		usage: "unlock-stake",
		summary:
			"start the unstake delay — bundlers stop accepting operations (STAKE_ADMIN_ROLE)",
		writes: true,
		run: async (context) => {
			warn(
				"an unlocked stake stops bundlers accepting this paymaster’s operations",
			);
			await submit(context, "unlock the stake", () =>
				context.paymaster.unlockStake(),
			);
		},
	},

	"withdraw-stake": {
		usage: "withdraw-stake <to>",
		summary:
			"withdraw the unlocked stake once the delay has elapsed (STAKE_ADMIN_ROLE)",
		writes: true,
		run: async (context) => {
			const to = requireAddress(context, 0, "to");
			await submit(context, `withdraw the stake to ${to}`, () =>
				context.paymaster.withdrawStake(to),
			);
		},
	},

	treasury: {
		usage: "treasury [<to> <eth>]",
		summary: "show accrued fees, or withdraw them (FEE_COLLECTOR_ROLE)",
		writes: true,
		run: async (context) => {
			if (context.args.positional.length === 0) {
				const treasury = await context.paymaster.getTreasury();
				emit({ treasuryWei: treasury });
				heading("Treasury");
				bullet(`accrued  ${eth(treasury)}`);
				return;
			}
			const to = requireAddress(context, 0, "to");
			const amount = requireEth(context, 1, "eth");
			await submit(context, `withdraw ${eth(amount)} of fees to ${to}`, () =>
				context.paymaster.withdrawFees(to, amount),
			);
		},
	},

	history: {
		usage: "history [--tenant <id>] [--limit <n>] [--windows <n>]",
		summary: "settled sponsorships, newest last",
		// A log read covers one window of blocks, so filling a --limit means stepping back window by
		// window. --windows caps how far: without it, a paymaster with no recent activity would walk
		// toward genesis looking for rows that are not there.
		run: async ({ paymaster, args }) => {
			const limit = count(args.flags.limit, 20, "--limit");
			const maxWindows = count(args.flags.windows, 5, "--windows");

			const records: SponsorshipRecord[] = [];
			let page = await paymaster.getSponsorships({
				tenantId: args.flags.tenant,
			});
			let oldest = page.fromBlock;
			const newest = page.toBlock;

			for (let window = 1; ; window++) {
				records.unshift(...page.records);
				oldest = page.fromBlock;
				if (records.length >= limit || !page.older || window >= maxWindows)
					break;
				page = await paymaster.getSponsorships({
					tenantId: args.flags.tenant,
					range: page.older,
				});
			}

			const shown = records.slice(-limit);
			emit({ fromBlock: oldest, toBlock: newest, records: shown });

			heading(
				`Sponsorships in blocks ${oldest}–${newest} (${records.length} found, showing ${shown.length})`,
			);
			if (records.length === 0) {
				bullet(
					`none settled in the last ${newest - oldest + 1n} blocks — raise --windows to look further back`,
				);
				return;
			}
			for (const record of shown) {
				out(
					`  ${pad(String(record.blockNumber), 10)}${pad(record.uuid, 38)}${record.success ? "ok  " : "fail"}  gas ${pad(eth(record.gasCostWei), 22)}fee ${eth(record.feeWei)}`,
				);
			}
			if (page.older)
				bullet(
					`older sponsorships may exist below block ${oldest} — raise --windows to reach them`,
				);
		},
	},

	watch: {
		usage: "watch [--tenant <id>]",
		summary: "stream sponsorships as they settle (ctrl-c to stop)",
		run: async ({ paymaster, args }) =>
			new Promise<void>((resolve) => {
				heading("Watching for sponsorships — ctrl-c to stop");
				const unwatch = paymaster.watchSponsorships(
					(record) => {
						out(
							`  ${record.uuid}  ${record.success ? "ok" : "fail"}  gas ${eth(record.gasCostWei)}  fee ${eth(record.feeWei)}  balance now ${eth(record.newBalanceWei)}`,
						);
					},
					{ tenantId: args.flags.tenant },
				);

				process.on("SIGINT", () => {
					unwatch();
					out("\n  stopped");
					resolve();
				});
			}),
	},

	help: {
		usage: "help",
		summary: "this list",
		run: async () => {
			out();
			out(
				"\x1b[1mgiano-paymaster\x1b[0m — manage a Giano sponsorship paymaster",
			);
			out();
			out(
				"  Reads need only --rpc. Writes need --private-key, and ask before they send.",
			);
			out();
			out("\x1b[1mCommands\x1b[0m");
			const width = 48;
			for (const [name, command] of Object.entries(commands)) {
				if (name === "help") continue;
				// A usage string longer than the column gets its summary on the next line rather than
				// pushing the whole table out of alignment.
				if (command.usage.length >= width)
					out(`  ${command.usage}\n  ${" ".repeat(width)}${command.summary}`);
				else out(`  ${pad(command.usage, width)}${command.summary}`);
			}
			out();
			out("\x1b[1mRoles\x1b[0m");
			out(
				`  timelocked: ${PAYMASTER_ROLE_NAMES.filter((role) => ROLE_DESCRIPTIONS[role].timelocked).join(", ")}`,
			);
			out(
				`  immediate:  ${PAYMASTER_ROLE_NAMES.filter((role) => !ROLE_DESCRIPTIONS[role].timelocked).join(", ")}`,
			);
			out();
			out("\x1b[1mTimelocked commands\x1b[0m");
			out(
				"  set-fee, set-withdraw-address, grant, revoke and upgrade call functions only the timelock",
			);
			out(
				"  may call once a deployment is handed off. With --timelock they send nothing and print the",
			);
			out(
				"  proposal instead: operation id, delay, ETA and the schedule / execute / cancel calldata.",
			);
			out(
				"  --safe-json <file>    also write the Safe Transaction Builder batch that schedules it",
			);
			out(
				"  --salt <0x..>         reproduce a proposal exactly (default: a random salt)",
			);
			out(
				"  --delay <duration>    schedule with a longer delay than required, e.g. 2d",
			);
			out();
			out("\x1b[1mGlobal flags\x1b[0m");
			out("  --rpc <url>           RPC_URL, default http://localhost:8545");
			out(
				"  --paymaster <0x..>    SPONSORSHIP_PAYMASTER_ADDRESS, else the contracts registry",
			);
			out(
				"  --private-key <0x..>  PAYMASTER_PRIVATE_KEY, else anvil key 0 on chain 31337",
			);
			out(
				"  --timelock <0x..>     GIANO_PAYMASTER_TIMELOCK: the paymaster's GianoTimelock",
			);
			out("  --json                machine-readable output");
			out("  --yes                 skip the confirmation prompt");
			out();
		},
	},
};

function requireRole(value: string): PaymasterRoleName {
	const normalised = value.toUpperCase() as PaymasterRoleName;
	if (!PAYMASTER_ROLE_NAMES.includes(normalised)) {
		throw new PaymasterSdkError(
			`unknown role "${value}". One of: ${PAYMASTER_ROLE_NAMES.join(", ")}`,
		);
	}
	return normalised;
}

// --- entry point -------------------------------------------------------------------------------

async function main(): Promise<void> {
	// `pnpm run <script> -- <args>` forwards a bare `--`, and the repo's root `paymaster` script
	// ends in one. Dropping leading separators means `pnpm paymaster status` and
	// `pnpm paymaster -- status` both work, rather than one of them reporting `unknown command "--"`.
	const argv = process.argv
		.slice(2)
		.filter(
			(token, index, all) =>
				!(
					token === "--" &&
					all.slice(0, index).every((earlier) => earlier === "--")
				),
		);
	const [name = "help", ...rest] = argv;
	const args = parseArgs(rest);
	jsonMode = args.flags.json === "true";

	const command = commands[name];
	if (!command)
		throw new PaymasterSdkError(
			`unknown command "${name}". Run \`giano-paymaster help\`.`,
		);
	if (name === "help") return command.run({} as Context);

	const rpcUrl =
		args.flags.rpc ?? process.env.RPC_URL ?? "http://localhost:8545";
	const transport = http(rpcUrl);
	const chainId = await createPublicClient({ transport }).getChainId();
	const isLocal = chainId === 31337;

	const chain: Chain = defineChain({
		id: chainId,
		name: `chain-${chainId}`,
		nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
		rpcUrls: { default: { http: [rpcUrl] } },
	});
	const publicClient = createPublicClient({ chain, transport });

	const timelockAddress =
		args.flags.timelock ?? process.env.GIANO_PAYMASTER_TIMELOCK;
	if (timelockAddress && !/^0x[0-9a-fA-F]{40}$/.test(timelockAddress))
		throw new PaymasterSdkError(
			`--timelock is not an address: ${timelockAddress}`,
		);
	// With a timelock, a timelocked command proposes rather than sends, so it needs no key at all.
	const writes =
		!(timelockAddress && command.timelocked) &&
		(typeof command.writes === "function"
			? command.writes(args)
			: command.writes === true);

	// The key is read here and turned into a signer here. The SDK is handed a wallet client that can
	// already sign and never sees the key itself — the same seam a browser wallet or a KMS uses.
	const rawKey =
		args.flags["private-key"] ??
		process.env.PAYMASTER_PRIVATE_KEY ??
		process.env.DEPLOYER_PRIVATE_KEY ??
		(isLocal ? ANVIL_KEY : undefined);

	let walletClient: GianoPaymasterClient["walletClient"];
	let account: Address = "0x0000000000000000000000000000000000000000";
	if (rawKey) {
		if (!/^0x[0-9a-fA-F]{64}$/.test(rawKey))
			throw new PaymasterSdkError(
				"--private-key must be a 0x-prefixed 32-byte hex string",
			);
		const signer = privateKeyToAccount(rawKey as Hex);
		account = signer.address;
		walletClient = createWalletClient({ account: signer, chain, transport });

		if (!isLocal && writes) {
			warn("signing with a raw private key on a non-local chain.");
			warn(
				"This CLI is a development tool: a key passed here is in your shell history and process",
			);
			warn(
				"list. Timelocked changes are proposed with --timelock, not signed here.",
			);
		}
	} else if (writes) {
		throw new PaymasterSdkError(
			`${name} sends a transaction, so it needs --private-key (or PAYMASTER_PRIVATE_KEY).` +
				(command.timelocked
					? " It is timelocked: pass --timelock <address> to print the proposal instead, which needs no key."
					: ""),
		);
	}

	const address = (args.flags.paymaster ??
		process.env.SPONSORSHIP_PAYMASTER_ADDRESS) as Address | undefined;
	const paymaster = address
		? new GianoPaymasterClient({ address, publicClient, walletClient })
		: await GianoPaymasterClient.fromRegistry({ publicClient, walletClient });

	await command.run({
		paymaster,
		timelock: timelockAddress
			? paymaster.timelock(timelockAddress as Address)
			: undefined,
		account,
		chainId,
		isLocal,
		assumeYes: args.flags.yes === "true" || jsonMode,
		args,
	});
}

main().catch((error: unknown) => {
	console.error(`\n\x1b[31m✗\x1b[0m ${(error as Error).message}\n`);
	process.exit(1);
});
