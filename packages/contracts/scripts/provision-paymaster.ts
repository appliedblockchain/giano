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
 *
 * `--role-holder-<role> <address>` gives one role to one holder (signer-admin, param-admin, pauser,
 * stake-admin, tenant-admin, fee-collector; fee-admin, withdraw-address-admin and upgrader are the
 * timelock's, granted by the hand-off). This key holds only the roles the run needs while it runs,
 * then hands them to their holders and gives them up.
 *
 * `--grant-all-to` grants every role to one address instead. That is a development convenience and
 * the script says so loudly: it collapses the separation D13 exists to create.
 */
import {
	Contract,
	formatEther,
	getAddress,
	isAddress,
	JsonRpcProvider,
	parseEther,
	Wallet,
} from "ethers";
import { getGianoDeployment } from "../addresses";
import { gianoPaymasterAbi, iEntryPointAbi } from "../generated";

/** Anvil's first account. Deterministic, funded, and never used anywhere real. */
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

function parseArgs(argv: string[]): Args {
	const flags: Record<string, string> = {};
	const repeated: Record<string, string[]> = {};
	for (let i = 0; i < argv.length; i++) {
		const token = argv[i];
		if (!token.startsWith("--")) continue;
		const key = token.slice(2);
		const next = argv[i + 1];
		const value = next && !next.startsWith("--") ? (i++, next) : "true";
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

/** `value` in wei, or an error naming what it was for. */
function ether(what: string, value: string): bigint {
	try {
		return parseEther(value);
	} catch {
		throw new Error(`${what} is not an ETH amount: ${value}`);
	}
}

function log(message: string): void {
	console.log(message);
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
	if (!isAddress(withdrawAddress))
		throw new Error(
			`tenant ${rawId}: withdraw address is not an address: ${withdrawAddress}`,
		);
	return {
		id: tenantIdToBytes16(rawId),
		raw: rawId,
		withdrawAddress: getAddress(withdrawAddress),
		slug,
		fundEth: fundEth ?? "0",
	};
}

async function main(): Promise<void> {
	const { flags, repeated } = parseArgs(process.argv.slice(2));

	const rpcUrl = flags.rpc ?? process.env.RPC_URL ?? "http://localhost:8545";
	const provider = new JsonRpcProvider(rpcUrl);
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

	const key =
		flags["private-key"] ??
		process.env.DEPLOYER_PRIVATE_KEY ??
		(chainId === 31337 ? ANVIL_KEY : undefined);
	if (!key)
		throw new Error("DEPLOYER_PRIVATE_KEY is required outside a local devnet");
	const wallet = new Wallet(key, provider);

	const paymaster = new Contract(
		getAddress(paymasterAddress),
		gianoPaymasterAbi,
		wallet,
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
	if (grantAllTo && !isAddress(grantAllTo))
		throw new Error(`--grant-all-to is not an address: ${grantAllTo}`);
	for (const flag of namedHolders) {
		const holder = flags[`role-holder-${flag}`];
		if (!isAddress(holder))
			throw new Error(`role holder for ${flag} is not an address: ${holder}`);
	}
	for (const signer of repeated.signer ?? [])
		if (!isAddress(signer))
			throw new Error(`--signer is not an address: ${signer}`);
	const stakeEth = flags["stake-eth"];
	const stakeWei =
		stakeEth && stakeEth !== "true"
			? ether("--stake-eth", stakeEth)
			: undefined;
	const tenants = (repeated.tenant ?? []).map(parseTenant);
	for (const tenant of tenants)
		ether(`tenant ${tenant.slug}'s funding`, tenant.fundEth);

	if (grantAllTo) {
		log("");
		log(
			`  ⚠ --grant-all-to ${grantAllTo}: every role on one address. Development only — this`,
		);
		log("    collapses the role separation the contract exists to enforce.");
	}

	/** Grants `roleName` to `holder` unless it already holds it. */
	const grant = async (roleName: string, holder: string) => {
		const role: string = await paymaster[roleName]();
		if (await paymaster.hasRole(role, holder)) {
			log(`  • ${roleName} already held by ${getAddress(holder)}`);
			return;
		}
		await (await paymaster.grantRole(role, getAddress(holder))).wait();
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
			if (!(await paymaster.hasRole(role, wallet.address))) continue;
			await (await paymaster.revokeRole(role, wallet.address)).wait();
			const holder = flags[`role-holder-${flag}`];
			log(
				`  ✓ gave up ${ROLE_FLAGS[flag]}${holder ? ` (held by ${getAddress(holder)})` : ""}`,
			);
		}
	};

	try {
		// --- roles -------------------------------------------------------------------------------
		if (grantAllTo)
			for (const roleName of Object.values(ROLE_FLAGS))
				await grant(roleName, grantAllTo);
		else {
			// With one holder per role, this key still has to authorise the signer, stake and register
			// the tenants below. It takes only the roles those steps need, for as long as they take, and
			// gives them up afterwards, whether or not the run gets that far (`releaseRunRoles`).
			const needs = [
				...(repeated.signer?.length ? (["signer-admin"] as const) : []),
				...(stakeWei !== undefined ? (["stake-admin"] as const) : []),
				...(tenants.length ? (["tenant-admin"] as const) : []),
			];
			for (const flag of needs) {
				const roleName = ROLE_FLAGS[flag];
				const role: string = await paymaster[roleName]();
				if (await paymaster.hasRole(role, wallet.address)) continue;
				await (await paymaster.grantRole(role, wallet.address)).wait();
				log(`  ✓ holds ${roleName} for this provisioning run`);
			}
		}

		// --- signing keys ------------------------------------------------------------------------
		for (const signer of repeated.signer ?? []) {
			if (await paymaster.isSigner(signer)) {
				log(`  • signer already authorised: ${getAddress(signer)}`);
				continue;
			}
			await (await paymaster.addSigner(getAddress(signer))).wait();
			log(`  ✓ authorised sponsorship signer ${getAddress(signer)}`);
		}

		// --- stake -------------------------------------------------------------------------------
		if (stakeWei !== undefined) {
			const unstakeDelay = Number(flags["unstake-delay"] ?? 86_400);
			const info = await entryPoint.getDepositInfo(paymasterAddress);
			if (info.staked && info.stake >= stakeWei) {
				log(`  • already staked: ${formatEther(info.stake)} ETH`);
			} else {
				await (
					await paymaster.addStake(unstakeDelay, { value: stakeWei })
				).wait();
				log(`  ✓ staked ${stakeEth} ETH with a ${unstakeDelay}s unstake delay`);
			}
		}

		// --- tenants -----------------------------------------------------------------------------
		for (const tenant of tenants) {
			const existing = await paymaster.getTenant(tenant.id);
			if (!existing.registered) {
				await (
					await paymaster.registerTenant(
						tenant.id,
						tenant.withdrawAddress,
						tenant.slug,
					)
				).wait();
				log(
					`  ✓ registered tenant ${tenant.slug} (${tenant.raw}) withdrawing to ${tenant.withdrawAddress}`,
				);
			} else {
				log(`  • tenant ${tenant.slug} already registered`);
			}

			if (tenant.fundEth !== "0") {
				await (
					await paymaster.depositFor(tenant.id, {
						value: parseEther(tenant.fundEth),
					})
				).wait();
				log(`  ✓ funded ${tenant.slug} with ${tenant.fundEth} ETH`);
			}
		}

		// --- hand the roles over -----------------------------------------------------------------
		if (!grantAllTo) {
			// The timelocked roles stay with ROLE_ADMIN, this bootstrap key, until contracts:handoff
			// gives them to the timelock and revokes them from everyone else, unless a holder is named.
			for (const flag of [
				"upgrader",
				"fee-admin",
				"withdraw-address-admin",
			] as const)
				if (!flags[`role-holder-${flag}`])
					await grant(ROLE_FLAGS[flag], wallet.address);
			for (const flag of namedHolders)
				await grant(
					ROLE_FLAGS[flag as keyof typeof ROLE_FLAGS],
					flags[`role-holder-${flag}`],
				);
		}
	} catch (error) {
		if (!grantAllTo) {
			log("");
			log(
				"  ✗ provisioning stopped part-way; giving up the roles this key held for the run.",
			);
			log(
				"    Rerun with the same arguments to resume: completed steps are skipped.",
			);
			await releaseRunRoles().catch((releaseError: unknown) =>
				console.error(
					`  ✗ could not give up the run's roles either (${(releaseError as Error).message}). This key may still hold ${RUN_ROLES.map((f) => ROLE_FLAGS[f]).join(", ")}: a rerun gives them up.`,
				),
			);
		}
		throw error;
	}
	if (!grantAllTo) await releaseRunRoles();

	// --- verify, and fail loudly if the deployment is not actually usable (R-24, R-60) ----------
	log("");
	log("Verifying:");
	const failures: string[] = [];

	const info = await entryPoint.getDepositInfo(paymasterAddress);
	if (!info.staked)
		failures.push(
			"paymaster is not staked — bundlers will reject its operations",
		);
	else log(`  ✓ staked: ${formatEther(info.stake)} ETH`);

	const deposit: bigint = await entryPoint.balanceOf(paymasterAddress);
	if (deposit === 0n)
		failures.push("EntryPoint deposit is empty — nothing can be sponsored");
	else log(`  ✓ deposit: ${formatEther(deposit)} ETH`);

	const signers: string[] = await paymaster.getSigners();
	if (signers.length === 0)
		failures.push("no authorised signing key — nothing can be authorised");
	else log(`  ✓ signers: ${signers.map((s) => getAddress(s)).join(", ")}`);

	let claims: bigint = await paymaster.treasury();
	let funded = false;
	for (const tenant of tenants) {
		const state = await paymaster.getTenant(tenant.id);
		claims += state.balance;
		if (state.balance > 0n) funded = true;
		log(
			`  ✓ ${tenant.slug}: ${formatEther(state.balance)} ETH available, ${formatEther(state.deficit)} ETH deficit`,
		);
	}
	if (tenants.length > 0 && !funded)
		failures.push(
			"no tenant holds a balance — a deployment is not complete until one does",
		);

	if (!grantAllTo)
		for (const flag of namedHolders) {
			const roleName = ROLE_FLAGS[flag as keyof typeof ROLE_FLAGS];
			const holder = getAddress(flags[`role-holder-${flag}`]);
			if (await paymaster.hasRole(await paymaster[roleName](), holder))
				log(`  ✓ ${roleName}: ${holder}`);
			else failures.push(`${roleName} is not held by ${holder}`);
		}

	if (!grantAllTo)
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

	if (claims > deposit)
		failures.push(
			`accounting invariant breached: claims ${formatEther(claims)} exceed deposit ${formatEther(deposit)}`,
		);
	else
		log(
			`  ✓ invariant holds, ${formatEther(deposit - claims)} ETH unattributed slack`,
		);

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
	console.error(`\n${(error as Error).message}`);
	process.exit(1);
});
