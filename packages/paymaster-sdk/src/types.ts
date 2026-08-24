import type { Address, Hash, Hex, TransactionReceipt } from 'viem';
import type { PaymasterRoleName } from './roles';

/** One tenant's on-chain record, exactly as the contract stores it. */
export type Tenant = {
  registered: boolean;
  enabled: boolean;
  hasFeeOverride: boolean;
  withdrawAddress: Address;
  /** Unspent funds, in wei. Spendable on sponsorships now. */
  balance: bigint;
  /** Gas already spent that the balance could not cover. Blocks the tenant until cleared. */
  deficit: bigint;
  feeWeiOverride: bigint;
};

/** A tenant record plus everything a dashboard would otherwise have to derive itself. */
export type TenantView = Tenant & {
  /** The `bytes16` id, as the contract keys it. */
  id: Hex;
  /** The same id as a UUID, which is how it appears off-chain. */
  uuid: string;
  /** The fee in force: the override if it has one, otherwise the deployment default. */
  effectiveFeeWei: bigint;
  /** Emitted at registration and never stored, so it is only available when logs were read. */
  slug?: string;
  /**
   * Whether this tenant can currently have work sponsored. A disabled tenant and a tenant in
   * deficit both fail validation, but for different reasons and with different fixes.
   */
  status: 'active' | 'disabled' | 'in-deficit' | 'unfunded';
};

/** The deployment-wide configuration an operator can change. */
export type PaymasterConfig = {
  entryPoint: Address;
  /** Platform fee per sponsored operation, before any per-tenant override. */
  defaultFeeWei: bigint;
  /** Gas units charged for the settlement step's own gas. */
  postOpGasAllowance: number;
  /** Basis points of the execution gas limit charged as a bound on the EntryPoint's penalty. */
  penaltyBps: number;
  /** Whether new sponsorships are being accepted. Withdrawals work either way. */
  paused: boolean;
};

/** The paymaster's position at the EntryPoint. */
export type StakeInfo = {
  /** The pooled deposit that actually pays for sponsored gas. */
  depositWei: bigint;
  /** The bond bundlers require before they will accept a validating paymaster's operations. */
  stakeWei: bigint;
  staked: boolean;
  unstakeDelaySec: number;
  /** Non-zero once unlocking has started; the stake is withdrawable after this timestamp. */
  withdrawTime: number;
};

/** Who holds one role. */
export type RoleHolders = {
  name: PaymasterRoleName | 'DEFAULT_ADMIN_ROLE';
  role: Hex;
  holders: readonly Address[];
};

/**
 * The solvency position, which is the property the whole design rests on:
 *
 *   Sum(tenant balances) + treasury <= EntryPoint.balanceOf(paymaster)
 *
 * "At most", never "equal" — the EntryPoint debits the deposit for costs that fall outside the
 * settlement figure, so the ledger is charged a deliberately generous upper bound and the
 * difference accumulates as unattributed slack. Slack is safe; equality would not be.
 */
export type Solvency = {
  tenantBalancesWei: bigint;
  treasuryWei: bigint;
  /** `tenantBalancesWei + treasuryWei` — everything the contract owes someone. */
  claimsWei: bigint;
  depositWei: bigint;
  /** `depositWei - claimsWei`. Expected to be positive and to grow slowly. */
  slackWei: bigint;
  /** False means an insolvency: stop issuing sponsorships and investigate. */
  holds: boolean;
};

/** Everything an overview screen needs, in one read. */
export type PaymasterOverview = {
  address: Address;
  chainId: number;
  config: PaymasterConfig;
  stake: StakeInfo;
  solvency: Solvency;
  tenants: readonly TenantView[];
  signers: readonly Address[];
  roles: readonly RoleHolders[];
};

export type HealthLevel = 'ok' | 'warn' | 'fail';

/** One health check, in the shape `giano-doctor` reports them. */
export type HealthCheck = {
  id: string;
  level: HealthLevel;
  label: string;
  detail: string;
  /** Present when the level is not `ok`: what to actually do about it. */
  remedy?: string;
};

export type HealthReport = {
  /** The worst level across every check. `fail` means the deployment is not usable as-is. */
  level: HealthLevel;
  checks: readonly HealthCheck[];
};

/**
 * The result of a write.
 *
 * The hash is returned as soon as the transaction is accepted, and `wait()` is separate so a
 * caller can show "submitted" before it shows "confirmed" — an admin panel that blocks on
 * confirmation with no feedback looks broken on a slow chain.
 */
export type WriteResult = {
  hash: Hash;
  wait: (confirmations?: number) => Promise<TransactionReceipt>;
};

/** A settled sponsorship, decoded from the `Sponsored` event. */
export type SponsorshipRecord = {
  tenantId: Hex;
  uuid: string;
  sender: Address;
  userOpHash: Hex;
  gasCostWei: bigint;
  feeWei: bigint;
  overheadWei: bigint;
  /** The tenant's balance immediately after settlement. */
  newBalanceWei: bigint;
  /** Whether the sponsored call itself succeeded. Gas is charged either way. */
  success: boolean;
  blockNumber: bigint;
  transactionHash: Hash;
};
