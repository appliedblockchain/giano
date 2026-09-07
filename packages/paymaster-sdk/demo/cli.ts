/**
 * A narrated walkthrough of every paymaster use case, written to be read as much as run.
 *
 * Each step prints what it is about to do, why the contract behaves that way, and the exact SDK
 * call — then executes it against a real chain and prints the result. Reading the output next to
 * this file is the fastest way to learn the SDK; running it is the fastest way to confirm a
 * deployment behaves the way the documentation claims.
 *
 * Usage:
 *   pnpm --filter @appliedblockchain/giano-paymaster-sdk demo                  # every step
 *   pnpm --filter @appliedblockchain/giano-paymaster-sdk demo -- --list        # names only
 *   pnpm --filter @appliedblockchain/giano-paymaster-sdk demo -- --step tenants
 *
 * Flags (all optional, each falling back to an env var):
 *   --rpc <url>           RPC_URL, default http://localhost:8545
 *   --paymaster <0x..>    SPONSORSHIP_PAYMASTER_ADDRESS, else the contracts registry for the chain
 *   --private-key <0x..>  DEPLOYER_PRIVATE_KEY, else anvil's first account on chain 31337
 *   --write               send transactions on a non-local chain (local chains write by default)
 *   --read-only           never send a transaction; write steps explain themselves instead
 *
 * The private key is read here, in the demo, and turned into a viem wallet client that is handed
 * to the SDK already able to sign. That is the whole point of the seam: the SDK is given a signer,
 * never a key, so the same calls work against a browser extension or a KMS without changing.
 */
import { GianoPaymasterClient, PaymasterSdkError, ROLE_DESCRIPTIONS, toTenantId, toTenantUuid, type PaymasterRoleName } from '../src/index';
import { createPublicClient, createWalletClient, defineChain, formatEther, http, parseEther, type Address, type Chain, type Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

/** Anvil's first account. Deterministic, funded, and never used anywhere real. */
const ANVIL_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

// --- tiny output helpers ---------------------------------------------------------------------

const log = (message = ''): void => {
  // eslint-disable-next-line no-console
  console.log(message);
};

const heading = (title: string): void => {
  log();
  log(`\x1b[1m${title}\x1b[0m`);
  log('─'.repeat(Math.min(title.length, 80)));
};

const note = (message: string): void => log(`  ${message}`);
const ok = (message: string): void => log(`  \x1b[32m✓\x1b[0m ${message}`);
const warn = (message: string): void => log(`  \x1b[33m⚠\x1b[0m ${message}`);
const bad = (message: string): void => log(`  \x1b[31m✗\x1b[0m ${message}`);

/** Prints the SDK call a step is about to make, so the output doubles as a code sample. */
const code = (snippet: string): void => {
  log();
  for (const line of snippet.trim().split('\n')) log(`    \x1b[36m${line}\x1b[0m`);
  log();
};

const eth = (wei: bigint): string => `${formatEther(wei)} ETH`;

// --- argument parsing ------------------------------------------------------------------------

function parseArgs(argv: string[]): Record<string, string> {
  const flags: Record<string, string> = {};
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (!token.startsWith('--')) continue;
    const next = argv[i + 1];
    flags[token.slice(2)] = next && !next.startsWith('--') ? (i++, next) : 'true';
  }
  return flags;
}

type Context = {
  paymaster: GianoPaymasterClient;
  account: Address;
  chainId: number;
  /** False when the demo must not send transactions; write steps then explain instead of acting. */
  canWrite: boolean;
  /** A tenant the demo registers for itself, so it never mutates one that matters. */
  demoTenantId: string;
};

type Step = {
  name: string;
  title: string;
  run: (context: Context) => Promise<void>;
};

// --- the walkthrough -------------------------------------------------------------------------

const steps: Step[] = [
  {
    name: 'connect',
    title: 'Connecting: reads need nothing but an RPC endpoint',
    run: async ({ paymaster, account, chainId }) => {
      note('A read-only client needs only a viem public client. Writes need a wallet client, which');
      note('the caller builds and the SDK never inspects — it has no way to reach a key.');
      code(`const paymaster = new GianoPaymasterClient({
  address: '${paymaster.address}',
  publicClient,          // reads
  walletClient,          // writes — omit for a read-only client
});`);

      const config = await paymaster.getConfig();
      ok(`paymaster ${paymaster.address} on chain ${chainId}`);
      ok(`bound to EntryPoint ${config.entryPoint}`);
      ok(`signing as ${account}`);
    },
  },

  {
    name: 'overview',
    title: 'Overview: the whole state in one call',
    run: async ({ paymaster }) => {
      note('An admin screen wants one consistent picture rather than a dozen reads that land');
      note('separately, so getOverview gathers configuration, stake, solvency, tenants, signers');
      note('and role holders together.');
      code(`const overview = await paymaster.getOverview();`);

      const overview = await paymaster.getOverview();
      ok(`default fee            ${eth(overview.config.defaultFeeWei)}`);
      ok(`post-op gas allowance  ${overview.config.postOpGasAllowance} gas`);
      ok(`penalty                ${overview.config.penaltyBps} bps`);
      ok(`accepting sponsorships ${overview.config.paused ? 'NO — paused' : 'yes'}`);
      ok(`stake                  ${eth(overview.stake.stakeWei)}${overview.stake.staked ? '' : ' (NOT STAKED)'}`);
      ok(`deposit                ${eth(overview.solvency.depositWei)}`);
      ok(`tenants                ${overview.tenants.length}`);
      ok(`signing keys           ${overview.signers.length}`);
    },
  },

  {
    name: 'solvency',
    title: 'Solvency: the invariant the whole design rests on',
    run: async ({ paymaster }) => {
      note('Sum(tenant balances) + treasury <= EntryPoint deposit.');
      note('"At most", never "equal": the EntryPoint debits the deposit for costs that fall outside');
      note('the figure settlement sees, so the ledger is charged a generous upper bound and the');
      note('difference accumulates as unattributed slack. Slack is safe. Equality would not be.');
      code(`const solvency = await paymaster.getSolvency();`);

      const solvency = await paymaster.getSolvency();
      ok(`tenant balances  ${eth(solvency.tenantBalancesWei)}`);
      ok(`treasury         ${eth(solvency.treasuryWei)}`);
      ok(`claims           ${eth(solvency.claimsWei)}`);
      ok(`deposit          ${eth(solvency.depositWei)}`);
      if (solvency.holds) ok(`invariant holds, ${eth(solvency.slackWei)} unattributed slack`);
      else bad('INVARIANT BREACHED — this is an insolvency; stop issuing sponsorships');
    },
  },

  {
    name: 'health',
    title: 'Health: the same checks the CI gate runs',
    run: async ({ paymaster }) => {
      note('Same thresholds and verdicts as giano-doctor, so a dashboard and the deployment gate');
      note('cannot disagree about whether a deployment is usable. Pure functions of an overview —');
      note('no extra round-trips, and every branch is testable without a chain.');
      code(`const health = await paymaster.getHealth();`);

      const health = await paymaster.getHealth();
      for (const check of health.checks) {
        const line = `${check.label}: ${check.detail}`;
        if (check.level === 'ok') ok(line);
        else if (check.level === 'warn') warn(line);
        else bad(line);
        if (check.remedy) note(`    → ${check.remedy}`);
      }
      log();
      note(`overall: ${health.level}`);
    },
  },

  {
    name: 'roles',
    title: 'Roles: no owner, no superuser',
    run: async ({ paymaster, account }) => {
      note('Every privileged action is gated by its own role, every role is administered by');
      note('ROLE_ADMIN (a timelock in production), and DEFAULT_ADMIN_ROLE is never granted.');
      note('The pairs are the design: the fee admin cannot collect the fees it sets, the fee');
      note('collector cannot change the rate, and no role at all can reach a tenant balance.');
      code(`const roles = await paymaster.getRoleHolders();
const mine  = await paymaster.getRolesOf(account);`);

      const [roles, mine] = await Promise.all([paymaster.getRoleHolders(), paymaster.getRolesOf(account)]);
      for (const entry of roles) {
        const holders = entry.holders.length > 0 ? entry.holders.join(', ') : '(nobody)';
        if (entry.name === 'DEFAULT_ADMIN_ROLE') {
          if (entry.holders.length === 0) ok('DEFAULT_ADMIN_ROLE: nobody — there is no superuser');
          else bad(`DEFAULT_ADMIN_ROLE: ${holders} — a superuser by another name`);
          continue;
        }
        ok(`${entry.name.padEnd(19)} ${holders}`);
        const description = ROLE_DESCRIPTIONS[entry.name as PaymasterRoleName];
        if (description) note(`    may ${description.may}; may not ${description.mayNot}`);
      }
      log();
      note(`the demo account holds: ${mine.length > 0 ? mine.join(', ') : 'no roles'}`);
    },
  },

  {
    name: 'tenants',
    title: 'Tenants: the roster is enumerable on-chain',
    run: async ({ paymaster }) => {
      note('The roster is an on-chain set, so a dashboard lists every tenant and its balance with');
      note('no backend and no log replay. The one exception is the slug, which is emitted at');
      note('registration and deliberately not stored — withSlugs recovers it from the logs.');
      code(`const tenants = await paymaster.listTenants({ withSlugs: true });`);

      const tenants = await paymaster.listTenants({ withSlugs: true });
      if (tenants.length === 0) {
        warn('no tenants registered yet — the register step below adds one');
        return;
      }
      for (const tenant of tenants) {
        ok(`${tenant.slug ?? '(no slug)'} — ${tenant.uuid}`);
        note(`    status ${tenant.status}, balance ${eth(tenant.balance)}, deficit ${eth(tenant.deficit)}`);
        note(`    fee ${eth(tenant.effectiveFeeWei)}${tenant.hasFeeOverride ? ' (override)' : ' (default)'}, withdraws to ${tenant.withdrawAddress}`);
      }
    },
  },

  {
    name: 'register',
    title: 'Registering a tenant (TENANT_ADMIN_ROLE)',
    run: async (context) => {
      const { paymaster, account, demoTenantId } = context;
      note('Tenant ids are UUIDs on the backend and bytes16 on-chain; the SDK accepts either and');
      note('normalises. Registration is once-only and there is no de-registration, so the roster');
      note('only ever grows. The slug is emitted for reconciliation, not stored.');
      code(`await paymaster.registerTenant('${demoTenantId}', withdrawAddress, 'demo-tenant');`);
      note(`as bytes16 that id is ${toTenantId(demoTenantId)}`);

      const existing = await paymaster.listTenants();
      if (existing.some((tenant) => tenant.id === toTenantId(demoTenantId))) {
        ok('demo tenant already registered — registration is once-only, so nothing to do');
        return;
      }
      if (!(await requireWrite(context, 'register the demo tenant'))) return;

      const result = await paymaster.registerTenant(demoTenantId, account, 'demo-tenant');
      note(`submitted ${result.hash}`);
      await result.wait();
      ok(`registered ${demoTenantId}, withdrawing to ${account}`);
    },
  },

  {
    name: 'fund',
    title: 'Funding a tenant (anyone may fund)',
    run: async (context) => {
      const { paymaster, demoTenantId } = context;
      note('depositFor is the only way funds enter the contract — a bare transfer reverts, because');
      note('money arriving without a tenant could never be attributed. Funding also clears any');
      note('outstanding deficit first, which is exactly what un-blocks a stuck tenant.');
      code(`await paymaster.depositFor('${demoTenantId}', parseEther('0.5'));`);

      if (!(await requireWrite(context, 'fund the demo tenant'))) return;

      const before = await paymaster.getTenant(demoTenantId);
      const result = await paymaster.depositFor(demoTenantId, parseEther('0.5'));
      await result.wait();
      const after = await paymaster.getTenant(demoTenantId);

      ok(`balance ${eth(before.balance)} → ${eth(after.balance)}`);
      if (before.deficit > after.deficit) ok(`deficit cleared: ${eth(before.deficit)} → ${eth(after.deficit)}`);
      ok(`the EntryPoint deposit rose by the same amount: ${eth(await paymaster.getDeposit())} total`);
    },
  },

  {
    name: 'fees',
    title: 'Fees: set by one role, collected by another (FEE_ADMIN_ROLE)',
    run: async (context) => {
      const { paymaster, demoTenantId } = context;
      note('A tenant can be given a fee that differs from the deployment default. The account that');
      note('sets fees deliberately cannot collect them — that separation is the point.');
      code(`await paymaster.setTenantFee('${demoTenantId}', true, parseEther('0.00002'));
await paymaster.setTenantFee('${demoTenantId}', false, 0n);  // back to the default`);

      const defaultFee = (await paymaster.getConfig()).defaultFeeWei;
      note(`deployment default is ${eth(defaultFee)}`);

      if (!(await requireWrite(context, 'set a fee override'))) return;

      await (await paymaster.setTenantFee(demoTenantId, true, parseEther('0.00002'))).wait();
      ok(`override in force: ${eth(await paymaster.feeFor(demoTenantId))}`);

      await (await paymaster.setTenantFee(demoTenantId, false, 0n)).wait();
      ok(`override cleared, back to the default: ${eth(await paymaster.feeFor(demoTenantId))}`);
    },
  },

  {
    name: 'enable',
    title: 'Disabling a tenant (TENANT_ADMIN_ROLE)',
    run: async (context) => {
      const { paymaster, demoTenantId } = context;
      note('Disabling stops new sponsorships for that tenant. It does not touch the balance and');
      note('does not trap it: the withdrawal path stays open, because an administrative action');
      note('must never be able to strand a tenant’s money.');
      code(`await paymaster.setTenantEnabled('${demoTenantId}', false);`);

      if (!(await requireWrite(context, 'disable and re-enable the demo tenant'))) return;

      await (await paymaster.setTenantEnabled(demoTenantId, false)).wait();
      ok(`status is now ${(await paymaster.getTenant(demoTenantId)).status}`);

      await (await paymaster.setTenantEnabled(demoTenantId, true)).wait();
      ok(`re-enabled, status ${(await paymaster.getTenant(demoTenantId)).status}`);
    },
  },

  {
    name: 'signers',
    title: 'Sponsorship signing keys (SIGNER_ADMIN_ROLE)',
    run: async (context) => {
      const { paymaster } = context;
      note('Only these keys can authorise a sponsorship. Revoking one takes effect immediately —');
      note('the contract checks set membership before it checks the signature, so a revoked key');
      note('never reaches the cryptography.');
      code(`const signers = await paymaster.getSigners();
await paymaster.addSigner(key);
await paymaster.removeSigner(key);`);

      const signers = await paymaster.getSigners();
      if (signers.length === 0) warn('no signing keys authorised — nothing can be sponsored');
      for (const signer of signers) ok(`authorised: ${signer}`);

      if (!(await requireWrite(context, 'add and remove a throwaway signing key'))) return;

      const throwaway = '0x00000000000000000000000000000000000f00d1' as Address;
      await (await paymaster.addSigner(throwaway)).wait();
      ok(`added ${throwaway} — isSigner: ${await paymaster.isSigner(throwaway)}`);
      await (await paymaster.removeSigner(throwaway)).wait();
      ok(`removed — isSigner: ${await paymaster.isSigner(throwaway)}`);
    },
  },

  {
    name: 'params',
    title: 'Operational parameters (PARAM_ADMIN_ROLE)',
    run: async (context) => {
      const { paymaster } = context;
      note('The overhead allowance and penalty basis points bound the costs settlement cannot');
      note('observe. They are charged as an upper bound on purpose: the ledger must fall at least');
      note('as fast as the deposit, or the invariant would drift. penaltyBps is capped at 5000.');
      code(`await paymaster.setPostOpGasAllowance(40_000);
await paymaster.setPenaltyBps(1000);   // the EntryPoint's own penalty is 10%`);

      const config = await paymaster.getConfig();
      ok(`postOpGasAllowance ${config.postOpGasAllowance}`);
      ok(`penaltyBps         ${config.penaltyBps}`);

      if (!(await requireWrite(context, 'nudge the post-op gas allowance and restore it'))) return;

      await (await paymaster.setPostOpGasAllowance(config.postOpGasAllowance + 1_000)).wait();
      ok(`raised to ${(await paymaster.getConfig()).postOpGasAllowance}`);
      await (await paymaster.setPostOpGasAllowance(config.postOpGasAllowance)).wait();
      ok(`restored to ${(await paymaster.getConfig()).postOpGasAllowance}`);
    },
  },

  {
    name: 'pause',
    title: 'Pausing (PAUSER_ROLE)',
    run: async (context) => {
      const { paymaster } = context;
      note('A pause halts acceptance of new sponsorships and nothing else. Withdrawals keep');
      note('working while paused — deliberately, because a pause must not trap funds.');
      code(`await paymaster.pause();
await paymaster.unpause();`);

      ok(`currently ${(await paymaster.isPaused()) ? 'paused' : 'not paused'}`);

      if (!(await requireWrite(context, 'pause and unpause'))) return;

      await (await paymaster.pause()).wait();
      ok(`paused: ${await paymaster.isPaused()}`);
      await (await paymaster.unpause()).wait();
      ok(`unpaused: ${!(await paymaster.isPaused())}`);
    },
  },

  {
    name: 'stake',
    title: 'Stake (STAKE_ADMIN_ROLE)',
    run: async (context) => {
      const { paymaster } = context;
      note('Bundlers reject an unstaked validating paymaster outright, which surfaces to a client');
      note('as an unexplained failure. The stake is separate from the deposit and the stake admin');
      note('cannot reach the deposit through it.');
      code(`await paymaster.addStake(parseEther('1'), 86_400);
await paymaster.unlockStake();          // starts the delay
await paymaster.withdrawStake(to);      // only after it elapses`);

      const stake = await paymaster.getStakeInfo();
      ok(`staked ${stake.staked}, ${eth(stake.stakeWei)}, unstake delay ${stake.unstakeDelaySec}s`);
      if (stake.withdrawTime > 0) warn(`unlocking — withdrawable from unix time ${stake.withdrawTime}`);
      note('not exercised here: unlocking a live stake would stop the chain sponsoring anything.');
    },
  },

  {
    name: 'treasury',
    title: 'Collecting fees (FEE_COLLECTOR_ROLE)',
    run: async (context) => {
      const { paymaster, account } = context;
      note('Withdrawal is capped at what has actually accrued. That cap is the whole reason the');
      note('collector cannot reach tenant funds — without it this path would drain the deposit.');
      code(`await paymaster.withdrawFees(to, amountWei);`);

      const treasury = await paymaster.getTreasury();
      ok(`accrued treasury: ${eth(treasury)}`);
      if (treasury === 0n) {
        note('nothing has accrued yet — fees accrue as operations settle, so this is expected on a');
        note('fresh chain. The next step shows what the refusal looks like when you overreach.');
        return;
      }
      if (!(await requireWrite(context, 'withdraw the accrued treasury'))) return;

      await (await paymaster.withdrawFees(account, treasury)).wait();
      ok(`withdrew ${eth(treasury)} to ${account}; treasury now ${eth(await paymaster.getTreasury())}`);
    },
  },

  {
    name: 'errors',
    title: 'Refusals: every revert arrives as a sentence',
    run: async (context) => {
      const { paymaster, demoTenantId } = context;
      note('Writes are simulated before they are signed, so an authorisation failure costs nothing');
      note('and arrives as a typed error naming the role — not an ABI trace. These calls are');
      note('*expected* to fail; that is what the step demonstrates.');
      code(`try {
  await paymaster.withdrawFees(to, parseEther('1000'));
} catch (error) {
  // ExceedsTreasuryError: "cannot withdraw 1000 ETH: only 0 ETH has accrued…"
}`);

      if (!context.canWrite) {
        note('skipped: refusals are demonstrated by simulating real calls, which needs a chain.');
        return;
      }

      await expectRefusal('withdrawing more than has accrued', () => paymaster.withdrawFees(context.account, parseEther('1000')));
      await expectRefusal('reading a tenant that was never registered', () =>
        paymaster.getTenant('00000000-0000-0000-0000-0000deadbeef'),
      );
      await expectRefusal('funding an unregistered tenant', () => paymaster.depositFor('00000000-0000-0000-0000-0000deadbeef', 1n));
      await expectRefusal('a malformed tenant id', () => paymaster.depositFor('not-a-uuid', 1n));
      await expectRefusal('overdrawing a tenant balance', () => paymaster.withdrawTenant(demoTenantId, parseEther('1000'), context.account));

      // The custody guarantee is the one worth demonstrating rather than asserting, so the demo
      // registers a tenant that withdraws somewhere else and then tries to take its money. The
      // account doing the asking holds ROLE_ADMIN and every other role on this chain, and it is
      // still refused — which is the whole claim.
      const foreignTenantId = '0de70000-0000-4000-8000-0000000000d2';
      const roster = await paymaster.listTenants();
      if (!roster.some((tenant) => tenant.id === toTenantId(foreignTenantId))) {
        await (await paymaster.registerTenant(foreignTenantId, '0x000000000000000000000000000000000000dEaD', 'demo-foreign-tenant')).wait();
      }
      await expectRefusal("withdrawing another tenant's balance while holding every role", () =>
        paymaster.withdrawTenant(foreignTenantId, 1n, context.account),
      );
    },
  },

  {
    name: 'history',
    title: 'History: settled sponsorships',
    run: async ({ paymaster }) => {
      note('Every settlement emits gas, fee and overhead separately, plus the resulting balance.');
      note('A shortfall that the balance could not cover is emitted as a deficit rather than');
      note('reverting — by then the network has already been paid, so refusing would revert work');
      note('that was genuinely done.');
      code(`const history = await paymaster.getSponsorships({ tenantId });
const unwatch = paymaster.watchSponsorships((record) => { /* live updates */ });`);

      const history = await paymaster.getSponsorships();
      if (history.length === 0) {
        note('no sponsorships settled on this chain yet — send a sponsored operation and re-run.');
        return;
      }
      for (const record of history.slice(-5)) {
        ok(`${record.uuid} — ${record.success ? 'succeeded' : 'reverted'} in block ${record.blockNumber}`);
        note(`    gas ${eth(record.gasCostWei)}, fee ${eth(record.feeWei)}, overhead ${eth(record.overheadWei)}`);
        note(`    balance after ${eth(record.newBalanceWei)}`);
      }
      note(`${history.length} sponsorship(s) total`);
    },
  },

  {
    name: 'withdraw',
    title: 'Tenant withdrawal: the one path no role can take',
    run: async (context) => {
      const { paymaster, account, demoTenantId } = context;
      note('Only a tenant’s registered withdrawal address can move its balance. No role defined by');
      note('this contract can — not TENANT_ADMIN, not FEE_COLLECTOR, not ROLE_ADMIN. The demo');
      note('registered itself as the withdrawal address, so it can demonstrate the happy path.');
      code(`await paymaster.withdrawTenant('${demoTenantId}', amountWei, to);`);

      const tenant = await paymaster.getTenant(demoTenantId).catch(() => undefined);
      if (!tenant) {
        warn('demo tenant not registered — run the register step first');
        return;
      }
      if (tenant.withdrawAddress.toLowerCase() !== account.toLowerCase()) {
        warn(`this account is not the withdrawal address (${tenant.withdrawAddress}), so it cannot withdraw`);
        return;
      }
      if (tenant.balance === 0n) {
        note('nothing to withdraw');
        return;
      }
      if (!(await requireWrite(context, 'withdraw a little of the demo tenant balance'))) return;

      const amount = tenant.balance / 10n;
      await (await paymaster.withdrawTenant(demoTenantId, amount, account)).wait();
      ok(`withdrew ${eth(amount)}; balance now ${eth((await paymaster.getTenant(demoTenantId)).balance)}`);
    },
  },
];

// --- step helpers ----------------------------------------------------------------------------

/** Runs a call that is supposed to fail, and prints the sentence the SDK produced. */
async function expectRefusal(what: string, call: () => Promise<unknown>): Promise<void> {
  try {
    await call();
    warn(`${what}: expected a refusal, but the call succeeded`);
  } catch (error) {
    const name = error instanceof Error ? error.constructor.name : 'Error';
    ok(`${what} → ${name}`);
    note(`    ${(error as Error).message}`);
  }
}

/** Gates a write, explaining rather than acting when the demo is not allowed to send. */
async function requireWrite(context: Context, what: string): Promise<boolean> {
  if (!context.canWrite) {
    note(`skipped (read-only): would ${what}. Pass --write to send transactions on this chain.`);
    return false;
  }
  return true;
}

/**
 * Grants the demo account the roles the walkthrough needs, when it can.
 *
 * Only possible where one account legitimately holds ROLE_ADMIN — a devnet or a first-run
 * testnet. In a real deployment every grant goes through the timelock, so this quietly does
 * nothing and the affected steps report the missing role instead.
 */
async function ensureRoles(paymaster: GianoPaymasterClient, account: Address, canWrite: boolean): Promise<void> {
  const needed: PaymasterRoleName[] = ['TENANT_ADMIN_ROLE', 'FEE_ADMIN_ROLE', 'FEE_COLLECTOR_ROLE', 'SIGNER_ADMIN_ROLE', 'PARAM_ADMIN_ROLE', 'PAUSER_ROLE'];

  if (!(await paymaster.hasRole('ROLE_ADMIN', account))) {
    warn(`${account} does not hold ROLE_ADMIN, so the demo cannot grant itself the roles it needs.`);
    note('Steps gated by a role it lacks will report that role rather than acting — which is');
    note('itself worth seeing, and is exactly what an operator would hit.');
    return;
  }

  const missing: PaymasterRoleName[] = [];
  for (const role of needed) if (!(await paymaster.hasRole(role, account))) missing.push(role);
  if (missing.length === 0) return;

  if (!canWrite) {
    warn(`missing ${missing.join(', ')} — pass --write to let the demo grant them`);
    return;
  }

  note(`granting the demo account ${missing.join(', ')} (it holds ROLE_ADMIN on this chain)`);
  for (const role of missing) await (await paymaster.grantRole(role, account)).wait();
}

// --- entry point -----------------------------------------------------------------------------

async function main(): Promise<void> {
  const flags = parseArgs(process.argv.slice(2).filter((token) => token !== '--'));

  if (flags.list) {
    log('Steps:');
    for (const step of steps) log(`  ${step.name.padEnd(10)} ${step.title}`);
    return;
  }

  const rpcUrl = flags.rpc ?? process.env.RPC_URL ?? 'http://localhost:8545';
  const transport = http(rpcUrl);

  // A minimal public client first, only to learn the chain id; the real ones are built with it.
  const chainId = await createPublicClient({ transport }).getChainId();
  const chain: Chain = defineChain({
    id: chainId,
    name: `chain-${chainId}`,
    nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
    rpcUrls: { default: { http: [rpcUrl] } },
  });

  const key = (flags['private-key'] ?? process.env.DEPLOYER_PRIVATE_KEY ?? (chainId === 31337 ? ANVIL_KEY : undefined)) as Hex | undefined;
  if (!key) throw new PaymasterSdkError('a private key is required outside a local devnet: pass --private-key or set DEPLOYER_PRIVATE_KEY');

  const publicClient = createPublicClient({ chain, transport });
  // The key is turned into a signer *here*, by the demo. The SDK receives the wallet client and
  // never the key — swap this line for an EIP-1193 or KMS transport and nothing else changes.
  const account = privateKeyToAccount(key);
  const walletClient = createWalletClient({ account, chain, transport });

  const address = (flags.paymaster ?? process.env.SPONSORSHIP_PAYMASTER_ADDRESS) as Address | undefined;
  const paymaster = address
    ? new GianoPaymasterClient({ address, publicClient, walletClient })
    : await GianoPaymasterClient.fromRegistry({ publicClient, walletClient });

  // Local chains are disposable, so they write by default; anywhere else has to opt in.
  const canWrite = flags['read-only'] ? false : flags.write === 'true' || chainId === 31337;

  log();
  log('\x1b[1mGiano paymaster SDK — walkthrough\x1b[0m');
  log(`  rpc        ${rpcUrl} (chain ${chainId})`);
  log(`  paymaster  ${paymaster.address}`);
  log(`  account    ${account.address}`);
  log(`  mode       ${canWrite ? 'read-write' : 'read-only (write steps explain themselves)'}`);

  const context: Context = {
    paymaster,
    account: account.address,
    chainId,
    canWrite,
    // Fixed, so re-running the demo re-uses its own tenant instead of registering a new one each
    // time — and never touches a tenant that matters.
    demoTenantId: '0de70000-0000-4000-8000-0000000000d1',
  };

  const selected = flags.step ? steps.filter((step) => step.name === flags.step) : steps;
  if (selected.length === 0) throw new PaymasterSdkError(`unknown step "${flags.step}". Run with --list to see them.`);

  if (!flags.step || flags.step === 'register') await ensureRoles(paymaster, account.address, canWrite);

  for (const step of selected) {
    heading(step.title);
    try {
      await step.run(context);
    } catch (error) {
      bad(`step "${step.name}" failed: ${(error as Error).message}`);
      if (flags.step) throw error;
    }
  }

  log();
  log(`Tenant id spellings, for reference: ${context.demoTenantId} is ${toTenantUuid(toTenantId(context.demoTenantId))} is ${toTenantId(context.demoTenantId)}`);
  log();
}

main().catch((error: unknown) => {
  // eslint-disable-next-line no-console
  console.error(`\n${(error as Error).message}\n`);
  process.exit(1);
});
