/**
 * giano-doctor — verify a chain's Giano deployment and inspect passkey wallets.
 *
 * Usage (run from the repo root):
 *   pnpm --filter @appliedblockchain/giano-contracts doctor -- chain \
 *     --rpc <url> --chain-id <id> [--factory 0x..] [--sponsorship-paymaster 0x..] \
 *     [--tenants <uuid,uuid>] [--role-admin 0x..] [--signers 0x..,0x..] [--executor 0x..]
 *
 *   pnpm --filter @appliedblockchain/giano-contracts doctor -- wallet \
 *     --rpc <url> --chain-id <id> [--factory 0x..] (--pubkey <x>,<y> | --address 0x..) [--nonce 0]
 *
 * Flags fall back to env: RPC_URL, CHAIN_ID, FACTORY_ADDRESS, ENTRYPOINT_ADDRESS,
 * SPONSORSHIP_PAYMASTER_ADDRESS, PAYMASTER_TENANT_IDS, PAYMASTER_ROLE_ADMIN, SPONSORSHIP_SIGNERS.
 * For registry chains (8453 / 84532 / 381185) the addresses default from the contracts registry.
 *
 * Exits non-zero if any CRITICAL check fails, so it doubles as a CI / pre-flight gate.
 *
 * Uses ethers (already a dependency of this package) — no build step required, mirrors
 * scripts/p256_deploy.ts and deploy/sepolia/print-funding.sh.
 */
import { Contract, JsonRpcProvider, concat, formatEther, getAddress, isAddress, toBeHex } from 'ethers';
import { ENTRYPOINT_V07_ADDRESS, getGianoDeployment, type GianoDeployment } from '../addresses';
import { CANONICAL_FACTORY, CANONICAL_IMPLEMENTATION } from '../canonical';
import { gianoPaymasterAbi, gianoSmartWalletFactoryAbi, iEntryPointAbi, multiOwnableAbi } from '../generated';

// --- well-known addresses (identical on every EVM chain) ---
const RIP7212_PRECOMPILE = '0x0000000000000000000000000000000000000100';
/** daimo p256-verifier — the in-contract FCL fallback webauthn-sol uses when RIP-7212 is absent. */
const P256_VERIFIER = '0xc2b78104907F722DABAc4C69f826a522B2754De4';
/** Chains on which a permissive test paymaster is a deployment failure, not a convenience. */
const PRODUCTION_CHAIN_IDS = [8453, 84532, 11155111];
/** Below this, sponsored operations start failing in ways that look like client bugs. */
const LOW_DEPOSIT_WEI = 20_000_000_000_000_000n; // 0.02 ETH
/** A validating paymaster needs a stake before bundlers will accept its operations at all. */
const MIN_STAKE_WEI = 100_000_000_000_000_000n; // 0.1 ETH

/** Arachnid deterministic-deployment proxy (CREATE2 factory). */
const CREATE2_FACTORY = '0x4e59b44847b379578588920ca78fbf26c0b4956c';

/** First valid Wycheproof P-256 vector (from lib/p256-verifier/test/P256Verifier.t.sol). */
const P256_VECTOR = {
  hash: '0xbb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023',
  r: 19738613187745101558623338726804762177711919211234071563652772152683725073944n,
  s: 34753961278895633991577816754222591531863837041401341770838584739693604822390n,
  x: 18614955573315897657680976650685450080931919913269223958732452353593824192568n,
  y: 90223116347859880166570198725387569567414254547569925327988539833150573990206n,
};

// --- tiny ✓/⚠/✗ checklist reporter ---
type Level = 'ok' | 'warn' | 'fail' | 'info';
const ICON: Record<Level, string> = { ok: '  ✓', warn: '  ⚠', fail: '  ✗', info: '  •' };
let hadFailure = false;

function report(level: Level, label: string, detail?: string) {
  if (level === 'fail') hadFailure = true;
  const line = `${ICON[level]} ${label}${detail ? `: ${detail}` : ''}`;
  // eslint-disable-next-line no-console
  console.log(line);
}

function section(title: string) {
  // eslint-disable-next-line no-console
  console.log(`\n${title}`);
}

// --- minimal arg parser: `doctor <cmd> --flag value ...` ---
function parseArgs(argv: string[]): { cmd?: string; flags: Record<string, string> } {
  const [cmd, ...rest] = argv;
  const flags: Record<string, string> = {};
  for (let i = 0; i < rest.length; i++) {
    const token = rest[i];
    if (token.startsWith('--')) {
      const key = token.slice(2);
      const next = rest[i + 1];
      if (next && !next.startsWith('--')) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = 'true';
      }
    }
  }
  return { cmd, flags };
}

function requireAddress(value: string | undefined, name: string): `0x${string}` {
  if (!value || !isAddress(value)) {
    throw new Error(`${name} is required and must be a 0x-prefixed 20-byte address (got: ${value ?? 'unset'})`);
  }
  return getAddress(value) as `0x${string}`;
}

/** Resolve the deployment addresses from flags/env, defaulting to the registry for known chains. */
function resolveDeployment(chainId: number, flags: Record<string, string>): Partial<GianoDeployment> {
  let registry: GianoDeployment | undefined;
  try {
    registry = getGianoDeployment(chainId);
  } catch {
    registry = undefined;
  }
  const pick = (flag: string, env: string, fallback?: `0x${string}`) =>
    (flags[flag] ?? process.env[env] ?? fallback) as `0x${string}` | undefined;
  return {
    entryPoint: pick('entrypoint', 'ENTRYPOINT_ADDRESS', registry?.entryPoint ?? ENTRYPOINT_V07_ADDRESS),
    factory: pick('factory', 'FACTORY_ADDRESS', registry?.factory),
    implementation: registry?.implementation,
    sponsorshipPaymaster: pick('sponsorship-paymaster', 'SPONSORSHIP_PAYMASTER_ADDRESS', registry?.sponsorshipPaymaster),
    sponsorshipPaymasterImplementation: registry?.sponsorshipPaymasterImplementation,
    testPaymaster: pick('test-paymaster', 'PAYMASTER_ADDRESS', registry?.testPaymaster),
  };
}

/**
 * The production paymaster's deployment-completeness checks (R-24), accounting invariant (R-34)
 * and role topology (R-55).
 *
 * These fail the exit code rather than warning. "Deployed but not staked" and "deployed but the
 * upgrade role is still on an operational key" both look fine from the outside and are exactly
 * the states a pre-flight gate exists to catch.
 */
async function checkSponsorshipPaymaster(
  provider: JsonRpcProvider,
  address: `0x${string}`,
  deployment: Partial<GianoDeployment>,
  entryPoint: string,
  flags: Record<string, string>,
): Promise<void> {
  section('Sponsorship paymaster (production)');
  const pmHasCode = await hasCode(provider, address);
  report(pmHasCode ? 'ok' : 'fail', 'sponsorship paymaster proxy deployed', address);
  if (!pmHasCode) return;

  const paymaster = new Contract(address, gianoPaymasterAbi, provider);
  const ep = new Contract(entryPoint, iEntryPointAbi, provider);

  // --- implementation matches the registry -------------------------------------------------
  try {
    // ERC-1967 implementation slot
    const slot = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';
    const raw = await provider.getStorage(address, slot);
    const impl = getAddress(`0x${raw.slice(-40)}`);
    report('info', 'implementation', impl);
    if (deployment.sponsorshipPaymasterImplementation) {
      const expected = getAddress(deployment.sponsorshipPaymasterImplementation);
      report(
        impl === expected ? 'ok' : 'warn',
        'implementation matches the registry',
        impl === expected ? impl : `${impl} vs ${expected} — an unannounced upgrade, or a stale registry`,
      );
    }
  } catch (error) {
    report('warn', 'read implementation slot', (error as Error).message);
  }

  // --- stake and deposit (R-24) --------------------------------------------------------------
  try {
    const info = await ep.getDepositInfo(address);
    const stake: bigint = info.stake ?? info[1];
    const deposit: bigint = info.deposit ?? info[0];
    const staked: boolean = info.staked ?? info[2];

    report(staked && stake >= MIN_STAKE_WEI ? 'ok' : 'fail', 'paymaster staked', `${formatEther(stake)} ETH`);
    if (!staked) {
      report('info', 'why this matters', 'bundlers reject an unstaked validating paymaster, which reads as a client bug');
    }
    report(deposit >= LOW_DEPOSIT_WEI ? 'ok' : 'fail', 'EntryPoint deposit', `${formatEther(deposit)} ETH`);
  } catch (error) {
    report('fail', 'read stake and deposit', (error as Error).message);
  }

  // --- the accounting invariant (R-34) -------------------------------------------------------
  const tenantIds = (flags['tenants'] ?? process.env.PAYMASTER_TENANT_IDS ?? '')
    .split(',')
    .map((t) => t.trim())
    .filter(Boolean);

  try {
    const deposit: bigint = await ep.balanceOf(address);
    const treasury: bigint = await paymaster.treasury();

    let tenantTotal = 0n;
    let anyFunded = false;
    for (const id of tenantIds) {
      const tenant = await paymaster.getTenant(id);
      const balance: bigint = tenant.balance;
      tenantTotal += balance;
      if (balance > 0n) anyFunded = true;
      if (tenant.deficit > 0n) {
        report('fail', `tenant ${id} carries a deficit`, `${formatEther(tenant.deficit)} ETH — that tenant cannot transact`);
      }
    }

    if (tenantIds.length === 0) {
      report('info', 'tenant balances', 'pass --tenants <id,id> to check per-tenant balances and the invariant');
    } else {
      const claims = tenantTotal + treasury;
      report(
        claims <= deposit ? 'ok' : 'fail',
        'accounting invariant (Σ balances + treasury ≤ deposit)',
        `${formatEther(claims)} ≤ ${formatEther(deposit)} ETH`,
      );
      if (claims > deposit) {
        report('info', 'this is an insolvency', 'claims exceed the deposit — stop issuing sponsorships and investigate');
      }
      report(
        anyFunded ? 'ok' : 'fail',
        'at least one tenant balance is funded',
        anyFunded ? `${formatEther(tenantTotal)} ETH across ${tenantIds.length} tenants` : 'none of the listed tenants holds a balance',
      );
      report('info', 'unattributed slack', `${formatEther(deposit - claims)} ETH (expected, and monitored for growth)`);
    }
  } catch (error) {
    report('fail', 'read the accounting invariant', (error as Error).message);
  }

  // --- roles (R-55) --------------------------------------------------------------------------
  try {
    const roleAdminRole: string = await paymaster.ROLE_ADMIN();
    const upgraderRole: string = await paymaster.UPGRADER_ROLE();

    const defaultAdminCount: bigint = await paymaster.getRoleMemberCount(
      '0x0000000000000000000000000000000000000000000000000000000000000000',
    );
    report(
      defaultAdminCount === 0n ? 'ok' : 'fail',
      'no DEFAULT_ADMIN_ROLE holder',
      defaultAdminCount === 0n ? 'there is no superuser' : `${defaultAdminCount} holder(s) — this is a superuser by another name`,
    );

    const expectedAuthority = (flags['role-admin'] ?? process.env.PAYMASTER_ROLE_ADMIN) as string | undefined;
    for (const [label, role] of [
      ['ROLE_ADMIN', roleAdminRole],
      ['UPGRADER_ROLE', upgraderRole],
    ] as const) {
      const count: bigint = await paymaster.getRoleMemberCount(role);
      const holders: string[] = [];
      for (let i = 0n; i < count; i++) holders.push(getAddress(await paymaster.getRoleMember(role, i)));

      if (count !== 1n) {
        report('fail', `${label} holders`, `${count} holder(s): ${holders.join(', ') || 'none'} — expected exactly one`);
      } else if (expectedAuthority && holders[0] !== getAddress(expectedAuthority)) {
        report('fail', `${label} holder`, `${holders[0]} — expected the timelock at ${getAddress(expectedAuthority)}`);
      } else {
        report(expectedAuthority ? 'ok' : 'warn', `${label} holder`, holders[0]);
        if (!expectedAuthority) {
          report('info', 'unverified', 'pass --role-admin <timelock> so this check asserts rather than reports');
        }
      }
    }

    const signers: string[] = await paymaster.getSigners();
    const expectedSigners = (flags['signers'] ?? process.env.SPONSORSHIP_SIGNERS ?? '')
      .split(',')
      .map((sig) => sig.trim())
      .filter(Boolean)
      .map((sig) => getAddress(sig));

    if (signers.length === 0) {
      report('fail', 'sponsorship signer set', 'empty — nothing can be authorised');
    } else if (expectedSigners.length === 0) {
      report('warn', 'sponsorship signer set', `${signers.map(getAddress).join(', ')} (pass --signers to assert)`);
    } else {
      const actual = signers.map(getAddress).sort().join(',');
      const expected = expectedSigners.sort().join(',');
      report(actual === expected ? 'ok' : 'fail', 'sponsorship signer set', actual === expected ? actual : `${actual} vs expected ${expected}`);
    }

    const paused: boolean = await paymaster.paused();
    report(paused ? 'warn' : 'ok', 'accepting new sponsorships', paused ? 'PAUSED — withdrawal still works' : 'not paused');
  } catch (error) {
    report('fail', 'read the role topology', (error as Error).message);
  }
}

async function hasCode(provider: JsonRpcProvider, address: string): Promise<boolean> {
  const code = await provider.getCode(address);
  return code !== undefined && code !== '0x';
}

/** Returns 'precompile' | 'verifier' | 'none' — how (if at all) this chain can verify P-256 sigs. */
async function checkP256(provider: JsonRpcProvider): Promise<'precompile' | 'verifier' | 'none'> {
  const input = concat([
    P256_VECTOR.hash,
    toBeHex(P256_VECTOR.r, 32),
    toBeHex(P256_VECTOR.s, 32),
    toBeHex(P256_VECTOR.x, 32),
    toBeHex(P256_VECTOR.y, 32),
  ]);
  const returnsOne = (result: string) => /^0x0{63}1$/.test(result);

  try {
    const precompileResult = await provider.call({ to: RIP7212_PRECOMPILE, data: input });
    if (returnsOne(precompileResult)) return 'precompile';
  } catch {
    /* precompile absent — fall through */
  }
  try {
    if (await hasCode(provider, P256_VERIFIER)) {
      const verifierResult = await provider.call({ to: P256_VERIFIER, data: input });
      if (returnsOne(verifierResult)) return 'verifier';
    }
  } catch {
    /* verifier absent */
  }
  return 'none';
}

async function connect(flags: Record<string, string>): Promise<{ provider: JsonRpcProvider; chainId: number }> {
  const rpc = flags.rpc ?? process.env.RPC_URL;
  if (!rpc) throw new Error('--rpc <url> is required (or set RPC_URL)');
  const expectedChainId = Number(flags['chain-id'] ?? process.env.CHAIN_ID);
  if (!expectedChainId) throw new Error('--chain-id <id> is required (or set CHAIN_ID)');

  const provider = new JsonRpcProvider(rpc);
  section(`Giano doctor — ${rpc}`);
  let onChainId: number;
  try {
    onChainId = Number((await provider.getNetwork()).chainId);
  } catch (error) {
    report('fail', 'RPC reachable', (error as Error).message);
    throw new Error('cannot reach the RPC endpoint');
  }
  report('ok', 'RPC reachable');
  if (onChainId === expectedChainId) {
    report('ok', 'chain id matches', String(onChainId));
  } else {
    report('fail', 'chain id mismatch', `RPC reports ${onChainId}, expected ${expectedChainId}`);
  }
  return { provider, chainId: expectedChainId };
}

async function doctorChain(flags: Record<string, string>) {
  const { provider, chainId } = await connect(flags);
  const deployment = resolveDeployment(chainId, flags);

  section('Contracts');
  const entryPoint = requireAddress(deployment.entryPoint, 'entryPoint');
  report((await hasCode(provider, entryPoint)) ? 'ok' : 'fail', 'EntryPoint v0.7 deployed', entryPoint);

  if (!deployment.factory) {
    report('fail', 'factory address', 'unknown — pass --factory or set FACTORY_ADDRESS (chain not in the registry)');
  } else {
    const factoryAddr = requireAddress(deployment.factory, 'factory');
    const factoryHasCode = await hasCode(provider, factoryAddr);
    report(factoryHasCode ? 'ok' : 'fail', 'GianoSmartWalletFactory deployed', factoryAddr);

    // MC-19: address identity across chains only holds when the factory sits at the frozen
    // canonical address. A chain that cannot offer it must not be admitted to a served list.
    if (getAddress(factoryAddr) === getAddress(CANONICAL_FACTORY)) {
      report('ok', 'factory address is canonical', CANONICAL_FACTORY);
    } else {
      report('fail', 'factory address is NOT canonical', `${factoryAddr} — canonical is ${CANONICAL_FACTORY}; this chain cannot join a multi-chain deployment (MC-19)`);
    }

    if (factoryHasCode) {
      try {
        const factory = new Contract(factoryAddr, gianoSmartWalletFactoryAbi, provider);
        const impl: string = await factory.implementation();
        const implHasCode = await hasCode(provider, impl);
        report(implHasCode ? 'ok' : 'fail', 'GianoSmartWallet implementation deployed', impl);
        if (getAddress(impl) !== getAddress(CANONICAL_IMPLEMENTATION)) {
          report('fail', 'implementation is NOT canonical', `${impl} — canonical is ${CANONICAL_IMPLEMENTATION} (MC-19)`);
        } else {
          report('ok', 'implementation is canonical', impl);
        }

        // MC-22: the live cross-check. A factory at the right address running different code
        // would pass every address comparison — asking it to derive an account address for a
        // fixed probe owner is what catches that. The probe owner is a well-known 64-byte
        // value that is never a real credential; the expected address is the same on every
        // canonical chain because the derivation has no chain-dependent term (MC-18).
        const probeOwner = `0x${'11'.repeat(64)}`;
        const probeAddress: string = await factory.getFunction('getAddress')([probeOwner], 0);
        report('info', 'probe account address (factory.getAddress, nonce 0)', probeAddress);
        report('info', 'cross-check', 'run this against every served chain — the probe address must be identical on all of them (MC-22)');
      } catch (error) {
        report('fail', 'read factory.implementation()', (error as Error).message);
      }
    }
  }

  const testPaymaster = deployment.testPaymaster;
  if (testPaymaster) {
    section('Permissive test paymaster (development only)');
    const addr = requireAddress(testPaymaster, 'test-paymaster');
    const pmHasCode = await hasCode(provider, addr);
    report(pmHasCode ? 'ok' : 'fail', 'test paymaster deployed', addr);
    if (PRODUCTION_CHAIN_IDS.includes(chainId)) {
      report('fail', 'test paymaster on a production chain', `chain ${chainId} must never carry a permissive paymaster`);
    }
    if (pmHasCode) {
      try {
        const ep = new Contract(entryPoint, iEntryPointAbi, provider);
        const deposit: bigint = await ep.balanceOf(addr);
        report(deposit >= LOW_DEPOSIT_WEI ? 'ok' : 'warn', 'test paymaster EntryPoint deposit', `${formatEther(deposit)} ETH`);
      } catch (error) {
        report('warn', 'read test paymaster deposit', (error as Error).message);
      }
    }
  }

  const sponsorshipPaymaster = deployment.sponsorshipPaymaster ?? undefined;
  if (sponsorshipPaymaster) {
    await checkSponsorshipPaymaster(provider, requireAddress(sponsorshipPaymaster, 'sponsorship-paymaster'), deployment, entryPoint, flags);
  }

  const executor = flags.executor ?? process.env.ALTO_EXECUTOR_ADDRESS;
  if (executor) {
    section('Bundler executor');
    const executorAddr = requireAddress(executor, 'executor');
    const balance = await provider.getBalance(executorAddr);
    const eth = formatEther(balance);
    report(balance >= 10_000_000_000_000_000n ? 'ok' : 'warn', 'executor native balance', `${executorAddr} — ${eth} ETH`);
    if (balance < 10_000_000_000_000_000n) {
      report('info', 'low executor balance', 'the executor fronts gas for every bundle — keep it funded');
    }
  }

  section('Passkey (P-256) verification support');
  const p256 = await checkP256(provider);
  if (p256 === 'precompile') {
    report('ok', 'P-256 via RIP-7212 precompile', 'cheap on-chain verification (0x100)');
  } else if (p256 === 'verifier') {
    report('ok', 'P-256 via FreshCryptoLib verifier', `${P256_VERIFIER} (works, higher gas than a precompile)`);
  } else {
    report('fail', 'P-256 verification unavailable', 'no RIP-7212 precompile and no deployed verifier');
    report('info', 'fix', 'deploy the verifier with scripts/p256_deploy.ts before passkey wallets can validate');
  }
  // MC-25: the deterministic-deployment mechanism must be present BEFORE contracts are
  // deployed — without it at this exact address, nothing deploys to the canonical addresses.
  report(
    (await hasCode(provider, CREATE2_FACTORY)) ? 'ok' : 'fail',
    'Arachnid CREATE2 factory (deterministic-deployment proxy)',
    `${CREATE2_FACTORY} — required before any Giano contract is deployed (adoption checklist step 1)`,
  );
}

async function doctorWallet(flags: Record<string, string>) {
  const { provider, chainId } = await connect(flags);
  const deployment = resolveDeployment(chainId, flags);
  const entryPoint = requireAddress(deployment.entryPoint, 'entryPoint');

  section('Wallet');
  let walletAddress: string;
  if (flags.address) {
    walletAddress = requireAddress(flags.address, 'address');
    report('info', 'target (given address)', walletAddress);
  } else if (flags.pubkey) {
    const factoryAddr = requireAddress(deployment.factory, 'factory');
    const [xRaw, yRaw] = flags.pubkey.split(',').map((v) => v.trim());
    if (!xRaw || !yRaw) throw new Error('--pubkey must be "<x>,<y>" (each a 32-byte hex or decimal value)');
    const x = toBeHex(BigInt(xRaw), 32);
    const y = toBeHex(BigInt(yRaw), 32);
    const ownerBytes = concat([x, y]); // 64-byte x‖y — the WebAuthn owner encoding
    const nonce = BigInt(flags.nonce ?? '0');
    const factory = new Contract(factoryAddr, gianoSmartWalletFactoryAbi, provider);
    walletAddress = await factory.getFunction('getAddress')([ownerBytes], nonce);
    report('info', 'counterfactual address (factory.getAddress)', `${walletAddress} (nonce ${nonce})`);
  } else {
    throw new Error('pass --address <0x..> or --pubkey <x>,<y>');
  }

  const deployed = await hasCode(provider, walletAddress);
  report(deployed ? 'ok' : 'info', deployed ? 'deployed on-chain' : 'not yet deployed (counterfactual)');
  report('info', 'native balance', `${formatEther(await provider.getBalance(walletAddress))} ETH`);

  try {
    const ep = new Contract(entryPoint, iEntryPointAbi, provider);
    const nonce: bigint = await ep.getNonce(walletAddress, 0n);
    report('info', 'EntryPoint nonce (key 0)', nonce.toString());
  } catch (error) {
    report('warn', 'read EntryPoint nonce', (error as Error).message);
  }

  if (deployed) {
    section('Owners');
    try {
      const wallet = new Contract(walletAddress, multiOwnableAbi, provider);
      const count: bigint = await wallet.ownerCount();
      const next: bigint = await wallet.nextOwnerIndex();
      report('ok', 'owner count', count.toString());
      for (let i = 0n; i < next; i++) {
        const owner: string = await wallet.ownerAtIndex(i);
        const bytes = (owner.length - 2) / 2;
        if (bytes === 0) continue; // removed slot
        if (bytes === 32) {
          report('info', `owner[${i}] address`, getAddress('0x' + owner.slice(-40)));
        } else if (bytes === 64) {
          report('info', `owner[${i}] P-256 passkey`, `x=${owner.slice(0, 66)} y=0x${owner.slice(66)}`);
        } else {
          report('warn', `owner[${i}] unknown encoding`, `${bytes} bytes`);
        }
      }
    } catch (error) {
      report('warn', 'read owners', (error as Error).message);
    }
  }
}

async function main() {
  // Strip standalone `--` separators (pnpm forwards them through the run-script passthrough).
  const argv = process.argv.slice(2).filter((token) => token !== '--');
  const { cmd, flags } = parseArgs(argv);
  if (cmd === 'chain') {
    await doctorChain(flags);
  } else if (cmd === 'wallet') {
    await doctorWallet(flags);
  } else {
    // eslint-disable-next-line no-console
    console.error(
      [
        'giano-doctor — verify a Giano deployment or inspect a wallet.',
        '',
        'Usage:',
        '  doctor chain  --rpc <url> --chain-id <id> [--factory 0x..] [--sponsorship-paymaster 0x..]',
        '                [--tenants <id,id>] [--role-admin 0x..] [--signers 0x..,0x..] [--executor 0x..]',
        '  doctor wallet --rpc <url> --chain-id <id> [--factory 0x..] (--pubkey <x>,<y> | --address 0x..) [--nonce 0]',
      ].join('\n'),
    );
    process.exit(2);
  }
  // eslint-disable-next-line no-console
  console.log('');
  if (hadFailure) {
    // eslint-disable-next-line no-console
    console.error('doctor: one or more critical checks FAILED');
    process.exit(1);
  }
  // eslint-disable-next-line no-console
  console.log('doctor: all critical checks passed');
}

void main().catch((error) => {
  // eslint-disable-next-line no-console
  console.error(`doctor: ${(error as Error).message}`);
  process.exit(1);
});
