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
 *     [--role-holder signer-admin=0x..] [--grant-all-to 0x..]
 *
 * `--grant-all-to` grants every role to one address. That is a development convenience and the
 * script says so loudly: it collapses the separation D13 exists to create.
 */
import { Contract, JsonRpcProvider, Wallet, formatEther, getAddress, isAddress, parseEther, zeroPadValue } from 'ethers';
import { getGianoDeployment } from '../addresses';
import { gianoPaymasterAbi, iEntryPointAbi } from '../generated';

/** Anvil's first account. Deterministic, funded, and never used anywhere real. */
const ANVIL_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

const ROLE_FLAGS = {
  'signer-admin': 'SIGNER_ADMIN_ROLE',
  'fee-admin': 'FEE_ADMIN_ROLE',
  'fee-collector': 'FEE_COLLECTOR_ROLE',
  'stake-admin': 'STAKE_ADMIN_ROLE',
  'tenant-admin': 'TENANT_ADMIN_ROLE',
  'param-admin': 'PARAM_ADMIN_ROLE',
  pauser: 'PAUSER_ROLE',
  upgrader: 'UPGRADER_ROLE',
} as const;

type Args = { flags: Record<string, string>; repeated: Record<string, string[]> };

function parseArgs(argv: string[]): Args {
  const flags: Record<string, string> = {};
  const repeated: Record<string, string[]> = {};
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (!token.startsWith('--')) continue;
    const key = token.slice(2);
    const next = argv[i + 1];
    const value = next && !next.startsWith('--') ? (i++, next) : 'true';
    flags[key] = value;
    (repeated[key] ??= []).push(value);
  }
  return { flags, repeated };
}

function log(message: string): void {
  // eslint-disable-next-line no-console
  console.log(message);
}

/**
 * The contract keys tenants by a 16-byte id. Giano's `tenants.id` is a UUID, which is already
 * immutable, already unique and never reused — so it is used directly rather than introducing a
 * second identifier that would then have to be kept in step.
 */
function tenantIdToBytes16(id: string): `0x${string}` {
  const hex = id.replace(/-/g, '').toLowerCase();
  if (/^[0-9a-f]{32}$/.test(hex)) return `0x${hex}`;
  if (/^0x[0-9a-f]{32}$/.test(id.toLowerCase())) return id.toLowerCase() as `0x${string}`;
  throw new Error(`tenant id must be a UUID or a 16-byte hex string, got: ${id}`);
}

type TenantSpec = { id: `0x${string}`; raw: string; withdrawAddress: string; slug: string; fundEth: string };

function parseTenant(spec: string): TenantSpec {
  const [rawId, withdrawAddress, slug, fundEth] = spec.split(':');
  if (!rawId || !withdrawAddress || !slug) {
    throw new Error(`--tenant expects <id>:<withdrawAddress>:<slug>[:<fundEth>], got: ${spec}`);
  }
  if (!isAddress(withdrawAddress)) throw new Error(`tenant ${rawId}: withdraw address is not an address: ${withdrawAddress}`);
  return { id: tenantIdToBytes16(rawId), raw: rawId, withdrawAddress: getAddress(withdrawAddress), slug, fundEth: fundEth ?? '0' };
}

async function main(): Promise<void> {
  const { flags, repeated } = parseArgs(process.argv.slice(2));

  const rpcUrl = flags.rpc ?? process.env.RPC_URL ?? 'http://localhost:8545';
  const provider = new JsonRpcProvider(rpcUrl);
  const chainId = Number((await provider.getNetwork()).chainId);

  let registryAddress: string | undefined;
  try {
    registryAddress = getGianoDeployment(chainId).sponsorshipPaymaster;
  } catch {
    registryAddress = undefined;
  }

  const paymasterAddress = flags.paymaster ?? process.env.SPONSORSHIP_PAYMASTER_ADDRESS ?? registryAddress;
  if (!paymasterAddress || !isAddress(paymasterAddress)) {
    throw new Error('--paymaster (or SPONSORSHIP_PAYMASTER_ADDRESS) is required; no registry entry for this chain');
  }

  const key = flags['private-key'] ?? process.env.DEPLOYER_PRIVATE_KEY ?? (chainId === 31337 ? ANVIL_KEY : undefined);
  if (!key) throw new Error('DEPLOYER_PRIVATE_KEY is required outside a local devnet');
  const wallet = new Wallet(key, provider);

  const paymaster = new Contract(getAddress(paymasterAddress), gianoPaymasterAbi, wallet);
  const entryPointAddress: string = await paymaster.entryPoint();
  const entryPoint = new Contract(entryPointAddress, iEntryPointAbi, provider);

  log(`Provisioning paymaster ${getAddress(paymasterAddress)} on chain ${chainId}`);
  log(`  role admin signer: ${wallet.address}`);

  const roleAdminRole: string = await paymaster.ROLE_ADMIN();
  if (!(await paymaster.hasRole(roleAdminRole, wallet.address))) {
    throw new Error(
      `${wallet.address} does not hold ROLE_ADMIN on ${paymasterAddress}. ` +
        'In a real deployment role grants go through the timelock, not through this script.',
    );
  }

  // --- roles ---------------------------------------------------------------------------------
  const grantAllTo = flags['grant-all-to'];
  if (grantAllTo) {
    log('');
    log(`  ⚠ --grant-all-to ${grantAllTo}: every role on one address. Development only — this`);
    log('    collapses the role separation the contract exists to enforce.');
  }

  for (const [flag, roleName] of Object.entries(ROLE_FLAGS)) {
    const holder = flags[`role-holder-${flag}`] ?? grantAllTo;
    if (!holder) continue;
    if (!isAddress(holder)) throw new Error(`role holder for ${flag} is not an address: ${holder}`);

    const role: string = await paymaster[roleName]();
    if (await paymaster.hasRole(role, holder)) {
      log(`  • ${roleName} already held by ${getAddress(holder)}`);
      continue;
    }
    await (await paymaster.grantRole(role, getAddress(holder))).wait();
    log(`  ✓ granted ${roleName} to ${getAddress(holder)}`);
  }

  // --- signing keys --------------------------------------------------------------------------
  for (const signer of repeated.signer ?? []) {
    if (!isAddress(signer)) throw new Error(`--signer is not an address: ${signer}`);
    if (await paymaster.isSigner(signer)) {
      log(`  • signer already authorised: ${getAddress(signer)}`);
      continue;
    }
    await (await paymaster.addSigner(getAddress(signer))).wait();
    log(`  ✓ authorised sponsorship signer ${getAddress(signer)}`);
  }

  // --- stake ---------------------------------------------------------------------------------
  const stakeEth = flags['stake-eth'];
  if (stakeEth && stakeEth !== 'true') {
    const unstakeDelay = Number(flags['unstake-delay'] ?? 86_400);
    const info = await entryPoint.getDepositInfo(paymasterAddress);
    if (info.staked && info.stake >= parseEther(stakeEth)) {
      log(`  • already staked: ${formatEther(info.stake)} ETH`);
    } else {
      await (await paymaster.addStake(unstakeDelay, { value: parseEther(stakeEth) })).wait();
      log(`  ✓ staked ${stakeEth} ETH with a ${unstakeDelay}s unstake delay`);
    }
  }

  // --- tenants -------------------------------------------------------------------------------
  const tenants = (repeated.tenant ?? []).map(parseTenant);
  for (const tenant of tenants) {
    const existing = await paymaster.getTenant(tenant.id);
    if (!existing.registered) {
      await (await paymaster.registerTenant(tenant.id, tenant.withdrawAddress, tenant.slug)).wait();
      log(`  ✓ registered tenant ${tenant.slug} (${tenant.raw}) withdrawing to ${tenant.withdrawAddress}`);
    } else {
      log(`  • tenant ${tenant.slug} already registered`);
    }

    if (tenant.fundEth !== '0') {
      await (await paymaster.depositFor(tenant.id, { value: parseEther(tenant.fundEth) })).wait();
      log(`  ✓ funded ${tenant.slug} with ${tenant.fundEth} ETH`);
    }
  }

  // --- verify, and fail loudly if the deployment is not actually usable (R-24, R-60) ----------
  log('');
  log('Verifying:');
  const failures: string[] = [];

  const info = await entryPoint.getDepositInfo(paymasterAddress);
  if (!info.staked) failures.push('paymaster is not staked — bundlers will reject its operations');
  else log(`  ✓ staked: ${formatEther(info.stake)} ETH`);

  const deposit: bigint = await entryPoint.balanceOf(paymasterAddress);
  if (deposit === 0n) failures.push('EntryPoint deposit is empty — nothing can be sponsored');
  else log(`  ✓ deposit: ${formatEther(deposit)} ETH`);

  const signers: string[] = await paymaster.getSigners();
  if (signers.length === 0) failures.push('no authorised signing key — nothing can be authorised');
  else log(`  ✓ signers: ${signers.map((s) => getAddress(s)).join(', ')}`);

  let claims: bigint = await paymaster.treasury();
  let funded = false;
  for (const tenant of tenants) {
    const state = await paymaster.getTenant(tenant.id);
    claims += state.balance;
    if (state.balance > 0n) funded = true;
    log(`  ✓ ${tenant.slug}: ${formatEther(state.balance)} ETH available, ${formatEther(state.deficit)} ETH deficit`);
  }
  if (tenants.length > 0 && !funded) failures.push('no tenant holds a balance — a deployment is not complete until one does');

  if (claims > deposit) failures.push(`accounting invariant breached: claims ${formatEther(claims)} exceed deposit ${formatEther(deposit)}`);
  else log(`  ✓ invariant holds, ${formatEther(deposit - claims)} ETH unattributed slack`);

  if (failures.length > 0) {
    log('');
    for (const failure of failures) log(`  ✗ ${failure}`);
    throw new Error(`provisioning incomplete: ${failures.length} check(s) failed`);
  }

  log('');
  log('Paymaster provisioned.');
}

main().catch((error: unknown) => {
  // eslint-disable-next-line no-console
  console.error(`\n${(error as Error).message}`);
  process.exit(1);
});
