import { gianoPaymasterAbi, getGianoDeployment, iEntryPointAbi } from '@appliedblockchain/giano-contracts';
import type { Account, Address, Chain, Hash, Hex, PublicClient, Transport, WalletClient } from 'viem';
import { SignerRequiredError, PaymasterSdkError, translateContractError } from './errors';
import { assessHealth } from './health';
import { DEFAULT_ADMIN_ROLE, PAYMASTER_ROLES, PAYMASTER_ROLE_NAMES, roleName, type PaymasterRoleName } from './roles';
import { toTenantId, toTenantUuid } from './tenant-id';
import type {
  HealthReport,
  PaymasterConfig,
  PaymasterOverview,
  RoleHolders,
  Solvency,
  SponsorshipRecord,
  StakeInfo,
  Tenant,
  TenantView,
  WriteResult,
} from './types';

/**
 * A viem public client. Reads only — every read path on this SDK needs one and nothing else.
 */
export type PaymasterPublicClient = PublicClient<Transport, Chain | undefined>;

/**
 * A viem wallet client. This is the signer seam, and the only one.
 *
 * The SDK never accepts a private key, a mnemonic or a keystore, and never constructs an account.
 * The caller builds a wallet client from whatever custody it actually uses — a browser extension
 * over EIP-1193, a hardware wallet, a KMS transport, a local account in a script — and hands it
 * over already able to sign. That keeps key material outside this package entirely, which is what
 * makes the same code safe to run in an admin browser tab and in an operations script.
 */
export type PaymasterWalletClient = WalletClient<Transport, Chain | undefined, Account | undefined>;

export type PaymasterClientConfig = {
  /** The paymaster proxy address. Stable across upgrades; this is what tenants fund. */
  address: Address;
  publicClient: PaymasterPublicClient;
  /** Omit for a read-only client. Every write throws {@link SignerRequiredError} without it. */
  walletClient?: PaymasterWalletClient;
};

/** How many tenants to pull per `getTenants` page. */
const TENANT_PAGE_SIZE = 200n;

/**
 * Client for the Giano sponsorship paymaster.
 *
 * Reads cover everything the contract exposes, including the tenant roster, which is enumerable
 * on-chain — so an overview needs no backend and no log replay. Writes are gated behind an
 * injected wallet, simulated before they are sent, and their reverts translated into named errors.
 *
 * ```ts
 * const paymaster = new GianoPaymasterClient({ address, publicClient });
 * const overview = await paymaster.getOverview();
 * ```
 */
export class GianoPaymasterClient {
  readonly address: Address;
  readonly publicClient: PaymasterPublicClient;
  readonly walletClient?: PaymasterWalletClient;

  private entryPointAddress?: Address;

  constructor(config: PaymasterClientConfig) {
    this.address = config.address;
    this.publicClient = config.publicClient;
    this.walletClient = config.walletClient;
  }

  /**
   * Resolves the paymaster address from the contracts registry for the client's chain.
   *
   * Throws when the chain has no registered sponsorship paymaster rather than falling back to the
   * testing paymaster: those are separate registry fields precisely so that no caller can pass one
   * where the other is meant.
   */
  static async fromRegistry(config: Omit<PaymasterClientConfig, 'address'>): Promise<GianoPaymasterClient> {
    const chainId = await config.publicClient.getChainId();
    const deployment = getGianoDeployment(chainId);
    if (!deployment.sponsorshipPaymaster) {
      throw new PaymasterSdkError(`chain ${chainId} has a Giano deployment but no registered sponsorship paymaster; pass the address explicitly`);
    }
    return new GianoPaymasterClient({ ...config, address: deployment.sponsorshipPaymaster });
  }

  /** The account writes will be sent from, or `undefined` on a read-only client. */
  get account(): Account | undefined {
    return this.walletClient?.account;
  }

  /** A copy of this client bound to a different (or a newly connected) wallet. */
  withWallet(walletClient: PaymasterWalletClient): GianoPaymasterClient {
    return new GianoPaymasterClient({ address: this.address, publicClient: this.publicClient, walletClient });
  }

  // -------------------------------------------------------------------------------------------
  // Reads — configuration
  // -------------------------------------------------------------------------------------------

  private read<T>(functionName: string, args: readonly unknown[] = []): Promise<T> {
    return this.publicClient.readContract({
      address: this.address,
      abi: gianoPaymasterAbi,
      functionName,
      args,
    } as never) as Promise<T>;
  }

  /** The EntryPoint this paymaster is bound to. Cached: it is immutable after initialisation. */
  async getEntryPoint(): Promise<Address> {
    this.entryPointAddress ??= await this.read<Address>('entryPoint');
    return this.entryPointAddress;
  }

  /**
   * Confirms there is actually a paymaster at this address.
   *
   * Worth its own call for the diagnosis rather than the detection. A read against an address with
   * no code does fail, but it fails as `the contract function "treasury" returned no data ("0x")`,
   * which reads like a broken ABI or a half-deployed contract. The actual cause is almost always a
   * wrong address or a console pointed at the wrong chain, and that is worth saying outright —
   * it is the single most likely first-run mistake.
   */
  async assertDeployed(): Promise<void> {
    const [code, chainId] = await Promise.all([this.publicClient.getCode({ address: this.address }), this.publicClient.getChainId()]);
    if (code === undefined || code === '0x') {
      throw new PaymasterSdkError(
        `no contract at ${this.address} on chain ${chainId}. Check the address and the RPC endpoint — this is a wrong-address or wrong-chain error, not a broken paymaster.`,
      );
    }
  }

  async getConfig(): Promise<PaymasterConfig> {
    const [entryPoint, defaultFeeWei, postOpGasAllowance, penaltyBps, paused] = await Promise.all([
      this.getEntryPoint(),
      this.read<bigint>('defaultFeeWei'),
      this.read<number>('postOpGasAllowance'),
      this.read<number>('penaltyBps'),
      this.read<boolean>('paused'),
    ]);
    return { entryPoint, defaultFeeWei, postOpGasAllowance, penaltyBps, paused };
  }

  isPaused(): Promise<boolean> {
    return this.read<boolean>('paused');
  }

  /** Accrued platform fees awaiting collection. */
  getTreasury(): Promise<bigint> {
    return this.read<bigint>('treasury');
  }

  /** The pooled deposit at the EntryPoint — the right-hand side of the solvency invariant. */
  getDeposit(): Promise<bigint> {
    return this.read<bigint>('getDeposit');
  }

  /** Deposit and stake together, read from the EntryPoint itself. */
  async getStakeInfo(): Promise<StakeInfo> {
    const entryPoint = await this.getEntryPoint();
    const info = (await this.publicClient.readContract({
      address: entryPoint,
      abi: iEntryPointAbi,
      functionName: 'getDepositInfo',
      args: [this.address],
    })) as { deposit: bigint; staked: boolean; stake: bigint; unstakeDelaySec: number; withdrawTime: number };

    return {
      depositWei: info.deposit,
      stakeWei: info.stake,
      staked: info.staked,
      unstakeDelaySec: Number(info.unstakeDelaySec),
      withdrawTime: Number(info.withdrawTime),
    };
  }

  // -------------------------------------------------------------------------------------------
  // Reads — tenants
  // -------------------------------------------------------------------------------------------

  getTenantCount(): Promise<bigint> {
    return this.read<bigint>('tenantCount');
  }

  /**
   * Whether this deployment exposes the on-chain tenant roster.
   *
   * False means a proxy that predates it, where the roster can only be reconstructed from
   * `TenantRegistered` logs — which {@link listTenants} does automatically, but which is slower,
   * needs log history the node may have pruned, and cannot see a tenant whose registration log is
   * out of range. Worth surfacing rather than hiding, because the fix is an upgrade.
   */
  async hasOnChainRoster(): Promise<boolean> {
    try {
      await this.getTenantCount();
      return true;
    } catch {
      return false;
    }
  }

  /** Every registered tenant id, straight from the on-chain roster. */
  getTenantIds(): Promise<readonly Hex[]> {
    return this.read<readonly Hex[]>('getTenantIds');
  }

  /** The fee in force for a tenant: its override if set, otherwise the deployment default. */
  feeFor(tenantId: string): Promise<bigint> {
    return this.read<bigint>('feeFor', [toTenantId(tenantId)]);
  }

  async getTenant(tenantId: string): Promise<TenantView> {
    const id = toTenantId(tenantId);
    const [tenant, effectiveFeeWei] = await Promise.all([this.read<Tenant>('getTenant', [id]), this.read<bigint>('feeFor', [id])]);
    if (!tenant.registered) {
      throw new PaymasterSdkError(`tenant ${id} is not registered on paymaster ${this.address}`);
    }
    return toTenantView(id, tenant, effectiveFeeWei);
  }

  /**
   * The whole tenant roster with each tenant's accounting record.
   *
   * Paged rather than one call, because `getTenants` returns an array whose size grows with the
   * roster and an unbounded read eventually exceeds the node's response limit. The paging is an
   * implementation detail — callers get the complete list.
   */
  async listTenants(options: { withSlugs?: boolean } = {}): Promise<readonly TenantView[]> {
    const defaultFeeWei = await this.read<bigint>('defaultFeeWei');

    let views: TenantView[];
    try {
      const total = await this.getTenantCount();
      views = [];
      for (let start = 0n; start < total; start += TENANT_PAGE_SIZE) {
        const [ids, records] = await this.read<[readonly Hex[], readonly Tenant[]]>('getTenants', [start, TENANT_PAGE_SIZE]);
        ids.forEach((id, index) => {
          const record = records[index];
          const fee = record.hasFeeOverride ? record.feeWeiOverride : defaultFeeWei;
          views.push(toTenantView(id, record, fee));
        });
      }
    } catch {
      // The roster views were added after the paymaster's first deployments, so a proxy that has
      // not been upgraded yet has no `tenantCount` and reverts here. Falling back to the log scan
      // — the only way to enumerate before those views existed — keeps this client usable against
      // both, rather than making every reader wait on an upgrade.
      views = await this.listTenantsFromLogs(defaultFeeWei);
    }

    if (!options.withSlugs) return views;

    const slugs = await this.getTenantSlugs();
    return views.map((view) => ({ ...view, slug: slugs.get(view.id) }));
  }

  /** Roster reconstruction for a paymaster predating the on-chain roster. See {@link listTenants}. */
  private async listTenantsFromLogs(defaultFeeWei: bigint): Promise<TenantView[]> {
    const ids = [...(await this.getTenantSlugs()).keys()];
    const records = await Promise.all(ids.map((id) => this.read<Tenant>('getTenant', [id])));

    return ids
      .map((id, index) => ({ id, record: records[index] }))
      .filter(({ record }) => record.registered)
      .map(({ id, record }) => toTenantView(id, record, record.hasFeeOverride ? record.feeWeiOverride : defaultFeeWei));
  }

  /**
   * Tenant slugs, recovered from `TenantRegistered`.
   *
   * The slug is emitted and deliberately not stored — it exists so the on-chain record can be read
   * against the backend's tenant table without a side channel — so this is the one piece of tenant
   * data that needs a log query rather than a view call.
   */
  async getTenantSlugs(fromBlock: bigint | 'earliest' = 'earliest'): Promise<Map<Hex, string>> {
    const logs = await this.publicClient.getContractEvents({
      address: this.address,
      abi: gianoPaymasterAbi,
      eventName: 'TenantRegistered',
      fromBlock,
      toBlock: 'latest',
    });

    const slugs = new Map<Hex, string>();
    for (const log of logs) {
      const args = log.args as { tenantId?: Hex; slug?: string };
      if (args.tenantId && args.slug !== undefined) slugs.set(args.tenantId, args.slug);
    }
    return slugs;
  }

  // -------------------------------------------------------------------------------------------
  // Reads — signers and roles
  // -------------------------------------------------------------------------------------------

  /** The authorised sponsorship signing keys. */
  getSigners(): Promise<readonly Address[]> {
    return this.read<readonly Address[]>('getSigners');
  }

  isSigner(signer: Address): Promise<boolean> {
    return this.read<boolean>('isSigner', [signer]);
  }

  hasRole(role: PaymasterRoleName, account: Address): Promise<boolean> {
    return this.read<boolean>('hasRole', [PAYMASTER_ROLES[role], account]);
  }

  /**
   * Every role and who holds it, `DEFAULT_ADMIN_ROLE` included.
   *
   * That last one is included precisely because it should be empty: a holder would be a superuser,
   * which this design does not have, and an overview that omitted the role could not show that.
   */
  async getRoleHolders(): Promise<readonly RoleHolders[]> {
    const roles: { name: PaymasterRoleName | 'DEFAULT_ADMIN_ROLE'; role: Hex }[] = [
      { name: 'DEFAULT_ADMIN_ROLE', role: DEFAULT_ADMIN_ROLE },
      ...PAYMASTER_ROLE_NAMES.map((name) => ({ name, role: PAYMASTER_ROLES[name] })),
    ];

    return Promise.all(
      roles.map(async ({ name, role }) => ({
        name,
        role,
        holders: await this.read<readonly Address[]>('getRoleMembers', [role]),
      })),
    );
  }

  /** Which of the paymaster's roles an account holds. Drives "what may I do here?" in a UI. */
  async getRolesOf(account: Address): Promise<readonly PaymasterRoleName[]> {
    const held = await Promise.all(PAYMASTER_ROLE_NAMES.map(async (name) => ((await this.hasRole(name, account)) ? name : undefined)));
    return held.filter((name): name is PaymasterRoleName => name !== undefined);
  }

  // -------------------------------------------------------------------------------------------
  // Reads — aggregates
  // -------------------------------------------------------------------------------------------

  /** The solvency invariant, evaluated. */
  async getSolvency(tenants?: readonly TenantView[]): Promise<Solvency> {
    const [resolved, treasuryWei, depositWei] = await Promise.all([
      tenants ? Promise.resolve(tenants) : this.listTenants(),
      this.getTreasury(),
      this.getDeposit(),
    ]);

    const tenantBalancesWei = resolved.reduce((sum, tenant) => sum + tenant.balance, 0n);
    const claimsWei = tenantBalancesWei + treasuryWei;
    return {
      tenantBalancesWei,
      treasuryWei,
      claimsWei,
      depositWei,
      slackWei: depositWei - claimsWei,
      holds: claimsWei <= depositWei,
    };
  }

  /**
   * Everything at once, for an overview screen.
   *
   * One call so a dashboard renders a single consistent picture rather than a screen that fills in
   * piecemeal and briefly shows a solvency figure computed from a half-loaded roster.
   */
  async getOverview(options: { withSlugs?: boolean } = {}): Promise<PaymasterOverview> {
    const [chainId, config, stake, tenants, signers, roles] = await Promise.all([
      this.publicClient.getChainId(),
      this.getConfig(),
      this.getStakeInfo(),
      this.listTenants({ withSlugs: options.withSlugs ?? true }),
      this.getSigners(),
      this.getRoleHolders(),
    ]);

    const solvency = await this.getSolvency(tenants);
    return { address: this.address, chainId, config, stake, solvency, tenants, signers, roles };
  }

  /**
   * The deployment's health, in the checks `giano-doctor` runs.
   *
   * Same thresholds and the same verdicts, so a panel and the CLI gate cannot disagree about
   * whether a deployment is usable.
   */
  async getHealth(): Promise<HealthReport> {
    const overview = await this.getOverview();
    return assessHealth(overview);
  }

  // -------------------------------------------------------------------------------------------
  // Reads — history
  // -------------------------------------------------------------------------------------------

  /**
   * Settled sponsorships, newest last.
   *
   * `tenantId` filters on the indexed topic, so the node does the filtering rather than the
   * caller pulling every sponsorship on the contract and discarding most of it.
   */
  async getSponsorships(options: { tenantId?: string; fromBlock?: bigint | 'earliest'; toBlock?: bigint | 'latest' } = {}): Promise<
    readonly SponsorshipRecord[]
  > {
    const logs = (await this.publicClient.getContractEvents({
      address: this.address,
      abi: gianoPaymasterAbi,
      eventName: 'Sponsored',
      args: options.tenantId ? { tenantId: toTenantId(options.tenantId) } : undefined,
      fromBlock: options.fromBlock ?? 'earliest',
      toBlock: options.toBlock ?? 'latest',
    } as never)) as unknown as readonly SponsoredLog[];

    return logs.map(toSponsorshipRecord);
  }

  /**
   * Calls `onSponsored` for each settled sponsorship as it lands. Returns an unwatch function.
   */
  watchSponsorships(onSponsored: (record: SponsorshipRecord) => void, options: { tenantId?: string } = {}): () => void {
    return this.publicClient.watchContractEvent({
      address: this.address,
      abi: gianoPaymasterAbi,
      eventName: 'Sponsored',
      args: options.tenantId ? { tenantId: toTenantId(options.tenantId) } : undefined,
      onLogs: (logs: readonly SponsoredLog[]) => {
        for (const log of logs) onSponsored(toSponsorshipRecord(log));
      },
    } as never);
  }

  // -------------------------------------------------------------------------------------------
  // Writes
  // -------------------------------------------------------------------------------------------

  /**
   * Simulate, then send.
   *
   * The simulation is not an optimisation — it is where the legible failure comes from. A write
   * sent blind reverts on-chain and costs gas to learn "you do not hold FEE_COLLECTOR_ROLE";
   * simulated first, the same fact arrives as a typed error before anything is signed.
   */
  private async send(functionName: string, args: readonly unknown[], operation: string, value?: bigint): Promise<WriteResult> {
    const walletClient = this.walletClient;
    if (!walletClient) throw new SignerRequiredError(operation);

    const account = walletClient.account;
    if (!account) {
      throw new PaymasterSdkError(`${operation} needs an account: the supplied wallet client has none. Pass one when creating it, or connect first.`);
    }

    try {
      const { request } = await this.publicClient.simulateContract({
        address: this.address,
        abi: gianoPaymasterAbi,
        functionName,
        args,
        account,
        value,
        chain: walletClient.chain ?? this.publicClient.chain,
      } as never);

      const hash = await walletClient.writeContract(request as never);
      return {
        hash,
        wait: (confirmations?: number) => this.publicClient.waitForTransactionReceipt({ hash, confirmations }),
      };
    } catch (error) {
      throw translateContractError(error, { operation, account: account.address, lookupRoleName: (role) => roleName(role) });
    }
  }

  // --- tenant administration (TENANT_ADMIN_ROLE) ---------------------------------------------

  /**
   * Registers a tenant. `slug` is emitted, not stored — see {@link getTenantSlugs}.
   *
   * Registration is once-only and there is no de-registration, so the roster only ever grows.
   */
  registerTenant(tenantId: string, withdrawAddress: Address, slug: string): Promise<WriteResult> {
    const id = toTenantId(tenantId);
    return this.send('registerTenant', [id, withdrawAddress, slug], `register tenant ${id}`);
  }

  /** Moves a tenant's exit. The new address is the only one that can withdraw the balance. */
  setTenantWithdrawAddress(tenantId: string, withdrawAddress: Address): Promise<WriteResult> {
    const id = toTenantId(tenantId);
    return this.send('setTenantWithdrawAddress', [id, withdrawAddress], `set the withdrawal address for tenant ${id}`);
  }

  /** Disabling stops new sponsorships for the tenant. It does not touch, or trap, its balance. */
  setTenantEnabled(tenantId: string, enabled: boolean): Promise<WriteResult> {
    const id = toTenantId(tenantId);
    return this.send('setTenantEnabled', [id, enabled], `${enabled ? 'enable' : 'disable'} tenant ${id}`);
  }

  // --- funding (anyone) and withdrawal (the tenant's own address) -----------------------------

  /**
   * Funds a tenant. Callable by anyone — the tenant, the platform, a finance system.
   *
   * Any outstanding deficit is cleared first, and clearing it is what un-blocks that tenant's
   * authorisations, so a funding call is also the fix for a tenant stuck in deficit.
   */
  depositFor(tenantId: string, amountWei: bigint): Promise<WriteResult> {
    const id = toTenantId(tenantId);
    return this.send('depositFor', [id], `fund tenant ${id}`, amountWei);
  }

  /**
   * Withdraws a tenant's unspent balance.
   *
   * Callable only by that tenant's registered withdrawal address — no role on this contract can
   * reach it — and deliberately available while the paymaster is paused, because a pause must not
   * trap funds.
   */
  withdrawTenant(tenantId: string, amountWei: bigint, to: Address): Promise<WriteResult> {
    const id = toTenantId(tenantId);
    return this.send('withdrawTenant', [id, amountWei, to], `withdraw from tenant ${id}`);
  }

  /** Withdraws accrued platform fees, capped at what has accrued. (FEE_COLLECTOR_ROLE) */
  withdrawFees(to: Address, amountWei: bigint): Promise<WriteResult> {
    return this.send('withdrawFees', [to, amountWei], 'withdraw treasury fees');
  }

  // --- signing keys (SIGNER_ADMIN_ROLE) -------------------------------------------------------

  addSigner(signer: Address): Promise<WriteResult> {
    return this.send('addSigner', [signer], `authorise sponsorship signer ${signer}`);
  }

  removeSigner(signer: Address): Promise<WriteResult> {
    return this.send('removeSigner', [signer], `revoke sponsorship signer ${signer}`);
  }

  // --- fees (FEE_ADMIN_ROLE) ------------------------------------------------------------------

  setDefaultFee(feeWei: bigint): Promise<WriteResult> {
    return this.send('setDefaultFee', [feeWei], 'set the default platform fee');
  }

  /** Sets or clears a tenant's fee override. Pass `hasOverride: false` to fall back to the default. */
  setTenantFee(tenantId: string, hasOverride: boolean, feeWei: bigint): Promise<WriteResult> {
    const id = toTenantId(tenantId);
    return this.send('setTenantFee', [id, hasOverride, hasOverride ? feeWei : 0n], `set the fee override for tenant ${id}`);
  }

  // --- operational parameters (PARAM_ADMIN_ROLE) ----------------------------------------------

  setPostOpGasAllowance(gasUnits: number): Promise<WriteResult> {
    return this.send('setPostOpGasAllowance', [gasUnits], 'set the post-op gas allowance');
  }

  /** Capped at 5000 by the contract; the EntryPoint's own penalty is 1000 (10%). */
  setPenaltyBps(bps: number): Promise<WriteResult> {
    return this.send('setPenaltyBps', [bps], 'set the penalty basis points');
  }

  // --- pause (PAUSER_ROLE) --------------------------------------------------------------------

  pause(): Promise<WriteResult> {
    return this.send('pause', [], 'pause the paymaster');
  }

  unpause(): Promise<WriteResult> {
    return this.send('unpause', [], 'unpause the paymaster');
  }

  // --- stake (STAKE_ADMIN_ROLE) ---------------------------------------------------------------

  /** Bundlers reject an unstaked validating paymaster, which reads to a client as a bug. */
  addStake(amountWei: bigint, unstakeDelaySec: number): Promise<WriteResult> {
    return this.send('addStake', [unstakeDelaySec], 'add stake', amountWei);
  }

  /** Starts the unstake delay. The stake is only withdrawable once it has elapsed. */
  unlockStake(): Promise<WriteResult> {
    return this.send('unlockStake', [], 'unlock the stake');
  }

  withdrawStake(to: Address): Promise<WriteResult> {
    return this.send('withdrawStake', [to], 'withdraw the stake');
  }

  // --- roles (ROLE_ADMIN) ---------------------------------------------------------------------

  grantRole(role: PaymasterRoleName, account: Address): Promise<WriteResult> {
    return this.send('grantRole', [PAYMASTER_ROLES[role], account], `grant ${role} to ${account}`);
  }

  revokeRole(role: PaymasterRoleName, account: Address): Promise<WriteResult> {
    return this.send('revokeRole', [PAYMASTER_ROLES[role], account], `revoke ${role} from ${account}`);
  }
}

/**
 * A decoded `Sponsored` log.
 *
 * Spelled out rather than inferred: the event filter is built conditionally, which widens viem's
 * return type to the undecoded shape, and an inferred `any` here would silently drop a field if
 * the event ever gained one.
 */
type SponsoredLog = {
  args: {
    tenantId: Hex;
    sender: Address;
    userOpHash: Hex;
    gasCostWei: bigint;
    feeWei: bigint;
    overheadWei: bigint;
    newBalance: bigint;
    success: boolean;
  };
  blockNumber: bigint | null;
  transactionHash: Hash | null;
};

function toSponsorshipRecord(log: SponsoredLog): SponsorshipRecord {
  const { args } = log;
  return {
    tenantId: args.tenantId,
    uuid: toTenantUuid(args.tenantId),
    sender: args.sender,
    userOpHash: args.userOpHash,
    gasCostWei: args.gasCostWei,
    feeWei: args.feeWei,
    overheadWei: args.overheadWei,
    newBalanceWei: args.newBalance,
    success: args.success,
    blockNumber: log.blockNumber ?? 0n,
    transactionHash: log.transactionHash ?? ('0x' as Hash),
  };
}

/** Adds the derived fields a caller would otherwise recompute at every call site. */
function toTenantView(id: Hex, tenant: Tenant, effectiveFeeWei: bigint): TenantView {
  return {
    ...tenant,
    id,
    uuid: toTenantUuid(id),
    effectiveFeeWei,
    status: tenant.deficit > 0n ? 'in-deficit' : !tenant.enabled ? 'disabled' : tenant.balance === 0n ? 'unfunded' : 'active',
  };
}
