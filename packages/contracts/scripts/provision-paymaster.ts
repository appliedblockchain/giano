/**
 * Provisions a deployed GianoPaymaster: grants roles, registers the signing key, stakes, registers
 * tenants and funds their balances.
 *
 * This is deliberately separate from the Ignition module. The module deploys artifacts whose
 * addresses must be identical for every operator; everything here is operator-specific, and in a
 * real deployment every role grant goes through the timelock rather than through this script.
 * What this script is for is the devnet, the e2e stack and a first-run testnet — the cases where
 * one account legitimately holds ROLE_ADMIN and the whole sequence can run unattended (R-60).
 *
 * A deployment is not complete until the paymaster is staked and at least one tenant balance is
 * funded (R-24), so the script verifies its own work and exits non-zero if it could not finish.
 *
 * Usage:
 *   RPC_URL=http://localhost:8545 DEPLOYER_PRIVATE_KEY=0x... \
 *   pnpm --filter @appliedblockchain/giano-contracts provision:paymaster -- \
 *     --paymaster 0x... \
 *     --signer 0x... \
 *     --stake-eth 1 --unstake-delay 86400 \
 *     --tenant <uuid>:<withdrawAddress>:<slug>:<fundEth> \
 *     [--tenant ...] \
 *     [--role-holder-signer-admin 0x.. --role-holder-pauser 0x.. …] | [--grant-all-to 0x..]
 *     [--signed-rpc] [--plan]
 *
 * Before its first transaction, a run projects the state it would leave and refuses to start when
 * that state fails the checks the run makes at its end. They are the checks the wrapper's doctor
 * makes after it: a stake of at least 0.1 ETH, an EntryPoint deposit of at least 0.02 ETH, exactly
 * the --signer signers, a funded tenant and no tenant deficit across the whole roster, the
 * accounting invariant, and ROLE_ADMIN and UPGRADER_ROLE each on this key alone until the hand-off.
 *
 * `--plan` runs every check of a real run, reads the chain, and lists each transaction the run
 * would send, with the ETH it carries. It sends nothing. It fails when the key holds less ETH than
 * those transactions carry plus gas, and when the state the run would leave fails the checks above.
 *
 * `--signed-rpc` signs every RPC request with the key, for an RPC that replaces `from` on an
 * unsigned eth_call or eth_estimateGas (Silent Data). Without it every role check fails there.
 *
 * `--role-holder-<role> <address>` gives one role to one holder (signer-admin, param-admin, pauser,
 * stake-admin, tenant-admin, fee-collector; fee-admin, withdraw-address-admin and upgrader are the
 * timelock's, granted by the hand-off). This key holds only the roles the run needs while it runs,
 * then hands them to their holders and gives them up.
 *
 * `--grant-all-to` grants every role to one address instead. That is a development convenience and
 * the script says so loudly: it collapses the separation D13 exists to create. When that address is
 * not this key, this key takes the run's roles and gives them up at the end, as with a holder per role,
 * and keeps the timelocked roles until the hand-off.
 */
import {
	Contract,
	FetchRequest,
	formatEther,
	getAddress,
	isAddress,
	JsonRpcProvider,
	Network,
	NonceManager,
	parseEther,
	toUtf8String,
	Wallet,
	ZeroAddress,
	ZeroHash,
} from "ethers";
import { getGianoDeployment } from "../addresses";
import { LOCAL_CHAIN_IDS } from "../chains";
import { redactRpcUrls } from "../deploy/config";
import { GAS_PRICE_HEADROOM } from "../deploy/funding";
import {
	LOW_DEPOSIT_WEI,
	MIN_STAKE_WEI,
	mainnetRoleProblems,
	provisioningIsMainnet,
	unstakeDelaySeconds,
} from "../deploy/provision-rules";
import { signatureHeaders } from "../deploy/signed-rpc";
import { gianoPaymasterAbi, iEntryPointAbi } from "../generated";

/**
 * Anvil's first account. Deterministic, funded on every local chain (LOCAL_CHAIN_IDS), and never
 * used anywhere real.
 */
const ANVIL_KEY =
	"0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

const ROLE_FLAGS = {
	"signer-admin": "SIGNER_ADMIN_ROLE",
	"fee-admin": "FEE_ADMIN_ROLE",
	"fee-collector": "FEE_COLLECTOR_ROLE",
	"stake-admin": "STAKE_ADMIN_ROLE",
	"tenant-admin": "TENANT_ADMIN_ROLE",
	"withdraw-address-admin": "WITHDRAW_ADDRESS_ADMIN_ROLE",
	"param-admin": "PARAM_ADMIN_ROLE",
	pauser: "PAUSER_ROLE",
	upgrader: "UPGRADER_ROLE",
} as const;

type Args = {
	flags: Record<string, string>;
	repeated: Record<string, string[]>;
};

/**
 * `text` without the RPC URLs this run may use. ethers and the fetch layer can quote the request
 * URL in an error, and a Silent Data URL carries a write token (G48).
 */
function redact(text: string): string {
	const argv = process.argv;
	const flagged = argv.includes("--rpc")
		? argv[argv.indexOf("--rpc") + 1]
		: undefined;
	return redactRpcUrls(text, [flagged, process.env.RPC_URL]);
}

/**
 * The gas a plan budgets for each transaction it would send. A grant, a revoke, addSigner and
 * registerTenant each use less than 200k gas; addStake and depositFor less than 100k.
 */
const PLAN_GAS_PER_TRANSACTION = 300_000n;

function parseArgs(argv: string[]): Args {
	const flags: Record<string, string> = {};
	const repeated: Record<string, string[]> = {};
	for (let i = 0; i < argv.length; i++) {
		const token = argv[i];
		if (!token.startsWith("--")) continue;
		const key = token.slice(2);
		const next = argv[i + 1];
		let value = "true";
		if (next && !next.startsWith("--")) {
			value = next;
			i++;
		}
		flags[key] = value;
		repeated[key] ??= [];
		repeated[key].push(value);
	}
	return { flags, repeated };
}

/**
 * The roles this key takes for a run with one holder per role, to authorise the signer, stake and
 * register tenants, and gives up at the end of it.
 */
const RUN_ROLES = ["signer-admin", "stake-admin", "tenant-admin"] as const;

/**
 * The timelocked roles. They stay with this key, the ROLE_ADMIN, until contracts:handoff gives them
 * to the timelock, unless a holder is named. --grant-all-to another address does not take them.
 */
const TIMELOCKED_ROLES = [
	"upgrader",
	"fee-admin",
	"withdraw-address-admin",
] as const;

/** Tenants per `getTenants` call, as the doctor reads the roster. */
const ROSTER_PAGE_SIZE = 50n;

/** `value` in wei, or an error naming what it was for. */
function ether(what: string, value: string): bigint {
	let wei: bigint;
	try {
		wei = parseEther(value);
	} catch {
		throw new Error(`${what} is not an ETH amount: ${value}`);
	}
	if (wei < 0n) throw new Error(`${what} is not an ETH amount: ${value}`);
	return wei;
}

/**
 * A provider that signs every request the way a Silent Data RPC verifies it, with the scheme in
 * deploy/signed-rpc.ts. One request per body, so each carries its own signature.
 */
function signedProvider(
	rpcUrl: string,
	chainId: number,
	key: string,
): JsonRpcProvider {
	const signer = new Wallet(key);
	const request = new FetchRequest(rpcUrl);
	request.preflightFunc = async (req) => {
		const headers = await signatureHeaders(
			chainId,
			req.body ? toUtf8String(req.body) : null,
			(message) => signer.signMessage(message),
		);
		for (const [name, value] of Object.entries(headers))
			req.setHeader(name, value);
		return req;
	};
	return new JsonRpcProvider(request, Network.from(chainId), {
		staticNetwork: true,
		batchMaxCount: 1,
		cacheTimeout: NO_REQUEST_CACHE,
	});
}

/**
 * ethers caches the result of an identical request for 250 ms by default. This script reads a
 * role or a balance, changes it, and reads it again, and on a fast node the second read can fall
 * inside that window and return the old value. So every request goes to the node. The nonces do
 * not depend on this: NonceManager counts them (see main).
 */
const NO_REQUEST_CACHE = -1;

function log(message: string): void {
	console.log(message);
}

/**
 * Throws unless `value` is an address other than the zero address. GianoPaymaster refuses the zero
 * address as a signer or a withdrawal address (`ZeroAddress`), and a role granted to it is lost. A
 * run would find out only at that transaction, after the ones before it went out.
 */
function checkAddress(what: string, value: string): void {
	if (!isAddress(value)) throw new Error(`${what} is not an address: ${value}`);
	if (getAddress(value) === ZeroAddress)
		throw new Error(`${what} is the zero address`);
}

/**
 * The contract keys tenants by a 16-byte id. Giano's `tenants.id` is a UUID, which is already
 * immutable, already unique and never reused — so it is used directly rather than introducing a
 * second identifier that would then have to be kept in step.
 */
function tenantIdToBytes16(id: string): `0x${string}` {
	const hex = id.replace(/-/g, "").toLowerCase();
	if (/^[0-9a-f]{32}$/.test(hex)) return `0x${hex}`;
	if (/^0x[0-9a-f]{32}$/.test(id.toLowerCase()))
		return id.toLowerCase() as `0x${string}`;
	throw new Error(
		`tenant id must be a UUID or a 16-byte hex string, got: ${id}`,
	);
}

type TenantSpec = {
	id: `0x${string}`;
	raw: string;
	withdrawAddress: string;
	slug: string;
	fundEth: string;
};

function parseTenant(spec: string): TenantSpec {
	const [rawId, withdrawAddress, slug, fundEth] = spec.split(":");
	if (!rawId || !withdrawAddress || !slug) {
		throw new Error(
			`--tenant expects <id>:<withdrawAddress>:<slug>[:<fundEth>], got: ${spec}`,
		);
	}
	checkAddress(`tenant ${rawId}: withdraw address`, withdrawAddress);
	const id = tenantIdToBytes16(rawId);
	// registerTenant reverts on it (UnknownTenant), after the run's earlier transactions went out.
	if (/^0x0{32}$/.test(id)) throw new Error(`tenant id is zero: ${rawId}`);
	return {
		id,
		raw: rawId,
		withdrawAddress: getAddress(withdrawAddress),
		slug,
		fundEth: fundEth ?? "0",
	};
}

type TenantOutcome = { slug: string; balance: bigint; deficit: bigint };

/**
 * What the end-of-run checks read: the paymaster after a run, or as a run would leave it. They are
 * the checks the doctor makes after the provisioning wrapper (deploy/contracts/provision-paymaster.sh)
 * runs this script, with the arguments the wrapper gives it.
 */
type Outcome = {
	staked: boolean;
	stake: bigint;
	/** The paymaster's EntryPoint deposit. */
	deposit: bigint;
	signers: string[];
	/** The --signer addresses. The wrapper's doctor expects exactly these signers. */
	namedSigners: string[];
	treasury: bigint;
	/** Every tenant on the paymaster's roster, as the doctor reads it. */
	tenants: TenantOutcome[];
	/** This key, which the wrapper's doctor expects to hold ROLE_ADMIN alone until the hand-off. */
	operator: string;
	roleAdmins: string[];
	upgraders: string[];
	/** Who holds UPGRADER_ROLE alone until the hand-off: its named holder, or this key. */
	upgrader: string;
	defaultAdmins: bigint;
};

/**
 * Whether the paymaster can sponsor (R-24, R-60), and whether the doctor would pass it: what passed,
 * and what failed. A run checks the state it would leave before its first transaction, and checks
 * the chain after its last. A plan checks the state the run would leave.
 */
function usabilityChecks(outcome: Outcome): {
	passed: string[];
	failures: string[];
} {
	const passed: string[] = [];
	const failures: string[] = [];
	if (!outcome.staked)
		failures.push(
			"paymaster is not staked — bundlers will reject its operations",
		);
	else if (outcome.stake < MIN_STAKE_WEI)
		failures.push(
			`stake ${formatEther(outcome.stake)} ETH is below the ${formatEther(MIN_STAKE_WEI)} ETH minimum — bundlers will reject its operations, and the doctor fails it`,
		);
	else passed.push(`staked: ${formatEther(outcome.stake)} ETH`);

	if (outcome.deposit === 0n)
		failures.push("EntryPoint deposit is empty — nothing can be sponsored");
	else if (outcome.deposit < LOW_DEPOSIT_WEI)
		failures.push(
			`EntryPoint deposit ${formatEther(outcome.deposit)} ETH is below the ${formatEther(LOW_DEPOSIT_WEI)} ETH minimum — sponsored operations start failing, and the doctor fails it. Fund the tenants with more.`,
		);
	else passed.push(`deposit: ${formatEther(outcome.deposit)} ETH`);

	if (outcome.signers.length === 0)
		failures.push("no authorised signing key — nothing can be authorised");
	else passed.push(`signers: ${outcome.signers.join(", ")}`);
	const unnamed =
		outcome.namedSigners.length > 0
			? outcome.signers.filter(
					(signer) => !outcome.namedSigners.includes(signer),
				)
			: [];
	if (unnamed.length > 0)
		failures.push(
			`signer(s) not named by --signer are authorised: ${unnamed.join(", ")}. The doctor expects exactly the named signers: remove the others first (removeSigner).`,
		);

	let claims = outcome.treasury;
	for (const tenant of outcome.tenants) {
		claims += tenant.balance;
		passed.push(
			`${tenant.slug}: ${formatEther(tenant.balance)} ETH available, ${formatEther(tenant.deficit)} ETH deficit`,
		);
		if (tenant.deficit > 0n)
			failures.push(
				`tenant ${tenant.slug} carries a deficit of ${formatEther(tenant.deficit)} ETH — it cannot transact, and the doctor fails it. Fund it with more than its deficit.`,
			);
	}
	if (
		outcome.tenants.length > 0 &&
		outcome.tenants.every((tenant) => tenant.balance === 0n)
	)
		failures.push(
			"no tenant holds a balance — a deployment is not complete until one does",
		);

	if (claims > outcome.deposit)
		failures.push(
			`accounting invariant breached: claims ${formatEther(claims)} exceed deposit ${formatEther(outcome.deposit)}`,
		);
	else
		passed.push(
			`invariant holds, ${formatEther(outcome.deposit - claims)} ETH unattributed slack`,
		);

	// The role topology the doctor checks until the hand-off (R-55).
	const alone = (holders: string[], expected: string) =>
		holders.length === 1 && holders[0] === expected;
	if (alone(outcome.roleAdmins, outcome.operator))
		passed.push(`ROLE_ADMIN: ${outcome.operator}`);
	else
		failures.push(
			`ROLE_ADMIN is held by ${outcome.roleAdmins.join(", ")}. The doctor expects this key, ${outcome.operator}, alone until the hand-off.`,
		);
	if (alone(outcome.upgraders, outcome.upgrader))
		passed.push(`UPGRADER_ROLE: ${outcome.upgrader}`);
	else
		failures.push(
			`UPGRADER_ROLE would be held by ${outcome.upgraders.join(", ") || "no one"}. The doctor expects ${outcome.upgrader} alone until the hand-off.`,
		);
	if (outcome.defaultAdmins > 0n)
		failures.push(
			`DEFAULT_ADMIN_ROLE has ${outcome.defaultAdmins} holder(s): a superuser, which the doctor fails`,
		);
	return { passed, failures };
}

async function main(): Promise<void> {
	const { flags, repeated } = parseArgs(process.argv.slice(2));

	const rpcUrl = flags.rpc ?? process.env.RPC_URL ?? "http://localhost:8545";
	let provider = new JsonRpcProvider(rpcUrl, undefined, {
		cacheTimeout: NO_REQUEST_CACHE,
	});
	const chainId = Number((await provider.getNetwork()).chainId);

	let registryAddress: string | undefined;
	try {
		registryAddress = getGianoDeployment(chainId).sponsorshipPaymaster;
	} catch {
		registryAddress = undefined;
	}

	const paymasterAddress =
		flags.paymaster ??
		process.env.SPONSORSHIP_PAYMASTER_ADDRESS ??
		registryAddress;
	if (!paymasterAddress || !isAddress(paymasterAddress)) {
		throw new Error(
			"--paymaster (or SPONSORSHIP_PAYMASTER_ADDRESS) is required; no registry entry for this chain",
		);
	}

	// An empty DEPLOYER_PRIVATE_KEY (an operator file with the line left blank) counts as unset.
	const key =
		flags["private-key"] ||
		process.env.DEPLOYER_PRIVATE_KEY ||
		((LOCAL_CHAIN_IDS as readonly number[]).includes(chainId)
			? ANVIL_KEY
			: undefined);
	// Checked after the chain id read, the only request sent so far. The signature covers the chain
	// id, so that read goes unsigned in deploy:cli too. On a local chain the anvil key signs.
	if (!key)
		throw new Error(
			flags["signed-rpc"]
				? "--signed-rpc needs DEPLOYER_PRIVATE_KEY to sign with"
				: "DEPLOYER_PRIVATE_KEY is required outside a local devnet",
		);
	if (flags["signed-rpc"]) provider = signedProvider(rpcUrl, chainId, key);
	const wallet = new Wallet(key, provider);
	// Reads the pending nonce once, then counts each transaction it sends. A load-balanced RPC can
	// answer the next nonce read from a node that has not yet seen the last receipt, and that read
	// would return a nonce already used. Every transaction this script sends goes through `signer`.
	const signer = new NonceManager(wallet);

	const paymaster = new Contract(
		getAddress(paymasterAddress),
		gianoPaymasterAbi,
		signer,
	);
	const entryPointAddress: string = await paymaster.entryPoint();
	const entryPoint = new Contract(entryPointAddress, iEntryPointAbi, provider);

	log(
		`Provisioning paymaster ${getAddress(paymasterAddress)} on chain ${chainId}`,
	);
	log(`  role admin signer: ${wallet.address}`);

	const roleAdminRole: string = await paymaster.ROLE_ADMIN();
	if (!(await paymaster.hasRole(roleAdminRole, wallet.address))) {
		// After the hand-off (contracts:handoff) the timelock holds ROLE_ADMIN and this bootstrap
		// script has nothing left to do: say so rather than reading as a misconfiguration.
		const timelock = process.env.PAYMASTER_TIMELOCK?.trim();
		if (timelock && (await paymaster.hasRole(roleAdminRole, timelock)))
			throw new Error(
				`ROLE_ADMIN on ${paymasterAddress} is held by the timelock ${getAddress(timelock)}: the roles were handed off, so this bootstrap provisioning no longer applies. ` +
					"Role changes now go through timelock proposals (docs/PAYMASTER-TIMELOCK-RUNBOOK.md §3); register and fund tenants with the TENANT_ADMIN_ROLE key through the giano-paymaster CLI or the operator console.",
			);
		throw new Error(
			`${wallet.address} does not hold ROLE_ADMIN on ${paymasterAddress}. ` +
				"In a real deployment role grants go through the timelock, not through this script.",
		);
	}

	// --- arguments: every one checked before the first transaction --------------------------------
	// A typo found after the signer, stake or tenants went out has spent ETH, and leaves this key
	// holding the roles it took for the run.
	const grantAllTo = flags["grant-all-to"];
	const namedHolders = Object.keys(ROLE_FLAGS).filter(
		(flag) => flags[`role-holder-${flag}`],
	);
	if (grantAllTo && namedHolders.length)
		throw new Error(
			"--grant-all-to and --role-holder-* are alternatives: one address for every role (development), or one holder per role",
		);
	if (grantAllTo) checkAddress("--grant-all-to", grantAllTo);
	// This key sends the signer, stake and tenant transactions, so it needs their roles while the run
	// lasts. It holds them as their holder only when --grant-all-to names this key itself.
	const takesRunRoles =
		!grantAllTo || getAddress(grantAllTo) !== getAddress(wallet.address);
	for (const flag of namedHolders)
		checkAddress(`role holder for ${flag}`, flags[`role-holder-${flag}`]);
	// The mainnet rules, here as well as in the operator wrapper, so running this script directly does
	// not skip them (#298 review).
	const mainnet = provisioningIsMainnet(chainId);
	const roleProblems = mainnetRoleProblems({
		mainnet,
		grantAllTo,
		holders: Object.fromEntries(
			namedHolders.map((flag) => [flag, flags[`role-holder-${flag}`]]),
		),
		operator: wallet.address,
	});
	if (roleProblems.length)
		throw new Error(`refusing to provision:\n  ${roleProblems.join("\n  ")}`);
	for (const signer of repeated.signer ?? []) checkAddress("--signer", signer);
	const stakeEth = flags["stake-eth"];
	const stakeWei =
		stakeEth && stakeEth !== "true"
			? ether("--stake-eth", stakeEth)
			: undefined;
	const unstakeDelay = unstakeDelaySeconds(flags["unstake-delay"] ?? "86400", {
		mainnet,
	});
	if (stakeWei !== undefined) {
		// The EntryPoint refuses an addStake whose unstake delay is shorter than the current one
		// (InvalidUnstakeDelay), also on a top-up. This check runs before the run's first transaction.
		const current = await entryPoint.getDepositInfo(paymasterAddress);
		const tops = !(current.staked && current.stake >= stakeWei);
		if (tops && BigInt(unstakeDelay) < BigInt(current.unstakeDelaySec))
			throw new Error(
				`--unstake-delay ${unstakeDelay}s is shorter than the paymaster's current unstake delay of ${current.unstakeDelaySec}s, and the EntryPoint does not let it decrease. Pass --unstake-delay ${current.unstakeDelaySec} or longer.`,
			);
	}
	const tenants = (repeated.tenant ?? []).map(parseTenant);
	for (const tenant of tenants)
		ether(`tenant ${tenant.slug}'s funding`, tenant.fundEth);

	if (grantAllTo) {
		log("");
		log(
			`  ⚠ --grant-all-to ${grantAllTo}: every role on one address. Development only — this`,
		);
		log("    collapses the role separation the contract exists to enforce.");
		if (takesRunRoles)
			log(
				"    The timelocked roles stay with this key until the hand-off, as the doctor expects.",
			);
	}

	const plan = flags.plan !== undefined;
	if (plan) {
		log("");
		log("Plan only: the transactions a run would send now. Nothing is sent.");
	}

	const namedSigners = (repeated.signer ?? []).map((s) => getAddress(s));
	const upgrader = getAddress(flags["role-holder-upgrader"] ?? wallet.address);
	/** The addresses that hold `roleName` now. */
	const holdersOf = async (roleName: string): Promise<string[]> => {
		const role: string =
			roleName === "DEFAULT_ADMIN_ROLE"
				? ZeroHash
				: await paymaster[roleName]();
		const count: bigint = await paymaster.getRoleMemberCount(role);
		const holders: string[] = [];
		for (let i = 0n; i < count; i++)
			holders.push(getAddress(await paymaster.getRoleMember(role, i)));
		return holders;
	};
	/**
	 * The paymaster's state, read as the doctor reads it: as it is now, or (`projected`) as this run
	 * would leave it, with the stake, signers, registrations, deposits and role grants the run sends.
	 */
	const readOutcome = async (projected: boolean): Promise<Outcome> => {
		const info = await entryPoint.getDepositInfo(paymasterAddress);
		const stakes =
			projected &&
			stakeWei !== undefined &&
			!(info.staked && info.stake >= stakeWei);
		const signers = (await paymaster.getSigners()).map((s: string) =>
			getAddress(s),
		);
		if (projected)
			for (const signer of namedSigners)
				if (!signers.includes(signer)) signers.push(signer);
		let deposit: bigint = await entryPoint.balanceOf(paymasterAddress);

		const roster = new Map<string, TenantOutcome>();
		const count: bigint = await paymaster.tenantCount();
		for (let start = 0n; start < count; start += ROSTER_PAGE_SIZE) {
			const page = await paymaster.getTenants(start, ROSTER_PAGE_SIZE);
			page.ids.forEach((id: string, i: number) => {
				roster.set(id.toLowerCase(), {
					slug: id,
					balance: page.records[i].balance,
					deficit: page.records[i].deficit,
				});
			});
		}
		for (const tenant of tenants) {
			const row = roster.get(tenant.id);
			// A tenant not on the roster is one the run registers; after a run, one it failed to.
			if (!row && !projected) continue;
			const state = row ?? { slug: tenant.slug, balance: 0n, deficit: 0n };
			state.slug = tenant.slug;
			if (projected) {
				// depositFor clears the tenant's deficit first and credits the rest to its balance,
				// while the EntryPoint deposit grows by the whole amount.
				const funding = parseEther(tenant.fundEth);
				let cleared = state.deficit;
				if (funding < cleared) cleared = funding;
				state.balance += funding - cleared;
				state.deficit -= cleared;
				deposit += funding;
			}
			roster.set(tenant.id, state);
		}

		const upgraders = await holdersOf("UPGRADER_ROLE");
		if (projected && !upgraders.includes(upgrader)) upgraders.push(upgrader);
		return {
			staked: info.staked || stakes,
			stake:
				stakes && stakeWei !== undefined ? info.stake + stakeWei : info.stake,
			deposit,
			signers,
			namedSigners,
			treasury: await paymaster.treasury(),
			tenants: [...roster.values()],
			operator: getAddress(wallet.address),
			roleAdmins: await holdersOf("ROLE_ADMIN"),
			upgraders,
			upgrader,
			defaultAdmins: BigInt((await holdersOf("DEFAULT_ADMIN_ROLE")).length),
		};
	};

	// The state the run would leave must pass the checks the run makes at its end, and the doctor's
	// after it. Checked before the first transaction, in a run as in a plan: a run that fails them
	// would spend ETH and then fail (G48 R3).
	const projection = usabilityChecks(await readOutcome(true));
	if (!plan && projection.failures.length > 0)
		throw new Error(
			`refusing to provision: the run would not complete:\n  ✗ ${projection.failures.join("\n  ✗ ")}`,
		);
	/** In a plan: the transactions not sent, the ETH they carry, and the run roles not taken. */
	let planned = 0;
	let plannedValue = 0n;
	const plannedRunRoles = new Set<string>();

	/**
	 * Sends one transaction and waits for it, and returns true. In a plan it only logs what it would
	 * send, and returns false.
	 */
	const send = async (
		action: string,
		transaction: () => Promise<{ wait: () => Promise<unknown> }>,
		value = 0n,
	): Promise<boolean> => {
		if (plan) {
			planned++;
			plannedValue += value;
			log(`  → would ${action}`);
			return false;
		}
		await (await transaction()).wait();
		return true;
	};

	/** Grants `roleName` to `holder` unless it already holds it. */
	const grant = async (roleName: string, holder: string) => {
		const role: string = await paymaster[roleName]();
		// In a plan, this key holds a run role it would take earlier in the run, though the chain does
		// not show it yet. The run sends that grant once.
		const takenInPlan =
			getAddress(holder) === getAddress(wallet.address) &&
			RUN_ROLES.some(
				(flag) => ROLE_FLAGS[flag] === roleName && plannedRunRoles.has(flag),
			);
		if (takenInPlan || (await paymaster.hasRole(role, holder))) {
			log(`  • ${roleName} already held by ${getAddress(holder)}`);
			return;
		}
		if (
			await send(`grant ${roleName} to ${getAddress(holder)}`, () =>
				paymaster.grantRole(role, getAddress(holder)),
			)
		)
			log(`  ✓ granted ${roleName} to ${getAddress(holder)}`);
	};

	/** This key's named holder for one of the run's roles is itself: it keeps that role. */
	const keeps = (flag: (typeof RUN_ROLES)[number]) => {
		const holder = flags[`role-holder-${flag}`];
		return Boolean(holder) && getAddress(holder) === getAddress(wallet.address);
	};

	/**
	 * Gives up every role of the run this key still holds, unless it is that role's named holder. The
	 * end state decides, not what this run granted, so a rerun also clears what a failed run left.
	 */
	const releaseRunRoles = async () => {
		for (const flag of RUN_ROLES) {
			if (keeps(flag)) continue;
			const role: string = await paymaster[ROLE_FLAGS[flag]]();
			if (
				!plannedRunRoles.has(flag) &&
				!(await paymaster.hasRole(role, wallet.address))
			)
				continue;
			const holder = flags[`role-holder-${flag}`] ?? grantAllTo;
			const heldBy = holder ? ` (held by ${getAddress(holder)})` : "";
			if (
				await send(`give up ${ROLE_FLAGS[flag]}${heldBy}`, () =>
					paymaster.revokeRole(role, wallet.address),
				)
			)
				log(`  ✓ gave up ${ROLE_FLAGS[flag]}${heldBy}`);
		}
	};

	try {
		// --- roles -------------------------------------------------------------------------------
		if (grantAllTo)
			for (const [flag, roleName] of Object.entries(ROLE_FLAGS))
				if (
					!takesRunRoles ||
					!(TIMELOCKED_ROLES as readonly string[]).includes(flag)
				)
					await grant(roleName, grantAllTo);
		if (takesRunRoles) {
			// When another address holds the roles, this key still has to authorise the signer, stake
			// and register the tenants below. It takes only the roles those steps need, for as long as
			// they take, and gives them up afterwards, whether or not the run gets that far
			// (`releaseRunRoles`).
			const needs = [
				...(repeated.signer?.length ? (["signer-admin"] as const) : []),
				...(stakeWei !== undefined ? (["stake-admin"] as const) : []),
				...(tenants.length ? (["tenant-admin"] as const) : []),
			];
			for (const flag of needs) {
				const roleName = ROLE_FLAGS[flag];
				const role: string = await paymaster[roleName]();
				if (await paymaster.hasRole(role, wallet.address)) continue;
				if (
					await send(`take ${roleName} for this provisioning run`, () =>
						paymaster.grantRole(role, wallet.address),
					)
				)
					log(`  ✓ holds ${roleName} for this provisioning run`);
				else plannedRunRoles.add(flag);
			}
		}

		// --- signing keys ------------------------------------------------------------------------
		for (const signer of repeated.signer ?? []) {
			if (await paymaster.isSigner(signer)) {
				log(`  • signer already authorised: ${getAddress(signer)}`);
				continue;
			}
			if (
				await send(`authorise sponsorship signer ${getAddress(signer)}`, () =>
					paymaster.addSigner(getAddress(signer)),
				)
			)
				log(`  ✓ authorised sponsorship signer ${getAddress(signer)}`);
		}

		// --- stake -------------------------------------------------------------------------------
		if (stakeWei !== undefined) {
			const info = await entryPoint.getDepositInfo(paymasterAddress);
			if (info.staked && info.stake >= stakeWei) {
				log(`  • already staked: ${formatEther(info.stake)} ETH`);
			} else if (
				await send(
					`stake ${stakeEth} ETH with a ${unstakeDelay}s unstake delay`,
					() => paymaster.addStake(unstakeDelay, { value: stakeWei }),
					stakeWei,
				)
			) {
				log(`  ✓ staked ${stakeEth} ETH with a ${unstakeDelay}s unstake delay`);
			}
		}

		// --- tenants -----------------------------------------------------------------------------
		for (const tenant of tenants) {
			const existing = await paymaster.getTenant(tenant.id);
			if (!existing.registered) {
				const registration = `tenant ${tenant.slug} (${tenant.raw}) withdrawing to ${tenant.withdrawAddress}`;
				if (
					await send(`register ${registration}`, () =>
						paymaster.registerTenant(
							tenant.id,
							tenant.withdrawAddress,
							tenant.slug,
						),
					)
				)
					log(`  ✓ registered ${registration}`);
			} else {
				log(`  • tenant ${tenant.slug} already registered`);
				if (getAddress(existing.withdrawAddress) !== tenant.withdrawAddress)
					log(
						`  ⚠ tenant ${tenant.slug} withdraws to ${getAddress(existing.withdrawAddress)}, not ${tenant.withdrawAddress}. This run does not change it: setTenantWithdrawAddress is a timelocked role's.`,
					);
			}

			const value = parseEther(tenant.fundEth);
			// depositFor reverts on 0 (ZeroAmount), so "0" and "0.0" both mean no deposit.
			if (value > 0n) {
				if (
					await send(
						`fund ${tenant.slug} with ${tenant.fundEth} ETH`,
						() => paymaster.depositFor(tenant.id, { value }),
						value,
					)
				)
					log(`  ✓ funded ${tenant.slug} with ${tenant.fundEth} ETH`);
			}
		}

		// --- hand the roles over -----------------------------------------------------------------
		if (takesRunRoles) {
			// The timelocked roles stay with ROLE_ADMIN, this bootstrap key, until contracts:handoff
			// gives them to the timelock and revokes them from everyone else, unless a holder is named.
			for (const flag of TIMELOCKED_ROLES)
				if (!flags[`role-holder-${flag}`])
					await grant(ROLE_FLAGS[flag], wallet.address);
			for (const flag of namedHolders)
				await grant(
					ROLE_FLAGS[flag as keyof typeof ROLE_FLAGS],
					flags[`role-holder-${flag}`],
				);
		}
	} catch (error) {
		// A plan took no role, so it has none to give up.
		if (takesRunRoles && !plan) {
			log("");
			log(
				"  ✗ provisioning stopped part-way; giving up the roles this key held for the run.",
			);
			log(
				"    Rerun with the same arguments to resume: completed steps are skipped.",
			);
			// NonceManager counts a transaction before sending it. One that failed before it was sent,
			// for example on gas estimation, leaves the count one ahead, so read it again from the node.
			signer.reset();
			await releaseRunRoles().catch((releaseError: unknown) =>
				console.error(
					`  ✗ could not give up the run's roles either (${redact((releaseError as Error).message)}). This key may still hold ${RUN_ROLES.map((f) => ROLE_FLAGS[f]).join(", ")}: a rerun gives them up.`,
				),
			);
		}
		throw error;
	}
	if (takesRunRoles) await releaseRunRoles();

	if (plan) {
		// The state the run would leave, projected before the first transaction (`projection`). The
		// run checks that state at its end, and the wrapper's doctor checks it again (G48 R3).
		const { passed, failures } = projection;

		// The run spends the ETH its transactions carry, plus gas. A key that holds less fails part-way
		// through the run, after the transactions before it went out (S8).
		const balance = await provider.getBalance(wallet.address);
		const { gasPrice } = await provider.getFeeData();
		const gas =
			BigInt(planned) *
			PLAN_GAS_PER_TRANSACTION *
			(gasPrice ?? 0n) *
			GAS_PRICE_HEADROOM;
		const needed = plannedValue + gas;
		log("");
		log(
			`Plan: ${planned} transaction(s), carrying ${formatEther(plannedValue)} ETH plus gas.`,
		);
		log(
			gasPrice === null
				? "  Gas: the gas price could not be read, so the check below leaves gas out."
				: `  Gas: up to ${formatEther(gas)} ETH (${PLAN_GAS_PER_TRANSACTION} gas per transaction at ${GAS_PRICE_HEADROOM}× the gas price; on an OP Stack chain the L1 data fee comes on top).`,
		);
		log(`  ${wallet.address} holds ${formatEther(balance)} ETH.`);
		if (balance < needed)
			failures.push(
				`${wallet.address} holds ${formatEther(balance)} ETH, less than the ${formatEther(needed)} ETH the run needs (${formatEther(plannedValue)} ETH it sends, plus gas). Fund it first (pnpm contracts:funding).`,
			);
		log("");
		log("After the run:");
		for (const line of passed) log(`  ✓ ${line}`);
		if (failures.length > 0)
			throw new Error(
				`the run would not complete:\n  ✗ ${failures.join("\n  ✗ ")}`,
			);
		log("Nothing was sent.");
		return;
	}

	// --- verify, and fail loudly if the deployment is not actually usable (R-24, R-60) ----------
	log("");
	log("Verifying:");
	const { passed, failures } = usabilityChecks(await readOutcome(false));
	for (const line of passed) log(`  ✓ ${line}`);

	if (!grantAllTo)
		for (const flag of namedHolders) {
			const roleName = ROLE_FLAGS[flag as keyof typeof ROLE_FLAGS];
			const holder = getAddress(flags[`role-holder-${flag}`]);
			if (await paymaster.hasRole(await paymaster[roleName](), holder))
				log(`  ✓ ${roleName}: ${holder}`);
			else failures.push(`${roleName} is not held by ${holder}`);
		}

	if (takesRunRoles)
		for (const flag of RUN_ROLES) {
			const roleName = ROLE_FLAGS[flag];
			if (
				!keeps(flag) &&
				(await paymaster.hasRole(await paymaster[roleName](), wallet.address))
			)
				failures.push(
					`this bootstrap key still holds ${roleName}, which only its named holder should`,
				);
		}

	if (failures.length > 0) {
		log("");
		for (const failure of failures) log(`  ✗ ${failure}`);
		throw new Error(
			`provisioning incomplete: ${failures.length} check(s) failed`,
		);
	}

	log("");
	log("Paymaster provisioned.");
}

main().catch((error: unknown) => {
	console.error(`\n${redact((error as Error).message)}`);
	process.exit(1);
});
