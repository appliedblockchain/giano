import { BaseError, ContractFunctionRevertedError, formatEther, type Address, type Hex } from 'viem';

/**
 * Errors.
 *
 * The paymaster reverts with typed custom errors, and every one of them is a sentence an operator
 * needs to read: "this tenant is in deficit", "you are not the withdrawal address", "you do not
 * hold FEE_COLLECTOR_ROLE". A raw viem revert buries that under an ABI-decoding trace, so the SDK
 * translates the ones an administrator can actually hit into named classes carrying the decoded
 * arguments, and — where the fix is not obvious from the failure — the fix.
 *
 * Deliberately a local base class rather than `GianoError` from `@appliedblockchain/giano-wallet-core`:
 * this package is meant to be usable by anything that talks to the paymaster, and making an
 * administration client depend on the wallet runtime to get an error base would be backwards.
 */

export type PaymasterSdkErrorOptions = {
  cause?: unknown;
};

/** Base class for everything this package throws. `instanceof` works across all subclasses. */
export class PaymasterSdkError extends Error {
  public override readonly name: string;
  public override readonly cause?: unknown;

  constructor(message: string, options?: PaymasterSdkErrorOptions) {
    super(message);
    this.name = this.constructor.name;
    this.cause = options?.cause;

    // Keep `instanceof` working when the package is transpiled down.
    Object.setPrototypeOf(this, this.constructor.prototype);

    const errorCtor = Error as unknown as { captureStackTrace?: (target: object, ctor: unknown) => void };
    if (errorCtor.captureStackTrace) errorCtor.captureStackTrace(this, this.constructor);
  }
}

/** A write was attempted on a client constructed without a wallet. */
export class SignerRequiredError extends PaymasterSdkError {
  constructor(operation: string) {
    super(
      `${operation} writes to the chain, but this client has no wallet. ` +
        'Construct it with `walletClient` — the SDK never holds a key, so the caller supplies the signer.',
    );
  }
}

/** The connected account does not hold the role the operation is gated by. */
export class MissingRoleError extends PaymasterSdkError {
  constructor(
    public readonly account: Address,
    public readonly role: Hex,
    /** The role's name, when the SDK recognises the hash. */
    public readonly roleName: string | undefined,
    public readonly operation: string,
    options?: PaymasterSdkErrorOptions,
  ) {
    super(
      `${account} cannot ${operation}: it does not hold ${roleName ?? role}. ` +
        'Roles are granted by the ROLE_ADMIN holder, which in a production deployment is a timelock.',
      options,
    );
  }
}

/** Only a tenant's registered withdrawal address may move that tenant's funds — no role can. */
export class NotWithdrawAddressError extends PaymasterSdkError {
  constructor(
    public readonly tenantId: Hex,
    public readonly caller: Address,
    options?: PaymasterSdkErrorOptions,
  ) {
    super(
      `${caller} is not the registered withdrawal address for tenant ${tenantId}, so it cannot withdraw that balance. ` +
        'This is deliberate: no role defined by the paymaster can reach tenant funds.',
      options,
    );
  }
}

export class UnknownTenantError extends PaymasterSdkError {
  constructor(
    public readonly tenantId: Hex,
    options?: PaymasterSdkErrorOptions,
  ) {
    super(`tenant ${tenantId} is not registered on this paymaster. Register it first (TENANT_ADMIN_ROLE).`, options);
  }
}

export class TenantAlreadyRegisteredError extends PaymasterSdkError {
  constructor(
    public readonly tenantId: Hex,
    options?: PaymasterSdkErrorOptions,
  ) {
    super(`tenant ${tenantId} is already registered. Registration is once-only; change its settings instead.`, options);
  }
}

/** A tenant carrying a deficit cannot authorise again until it funds. */
export class TenantInDeficitError extends PaymasterSdkError {
  constructor(
    public readonly tenantId: Hex,
    public readonly deficitWei: bigint,
    options?: PaymasterSdkErrorOptions,
  ) {
    super(
      `tenant ${tenantId} carries a ${formatEther(deficitWei)} ETH deficit and cannot transact until it is cleared. ` +
        'Funding the tenant clears the deficit first, then credits the remainder.',
      options,
    );
  }
}

export class InsufficientTenantBalanceError extends PaymasterSdkError {
  constructor(
    public readonly tenantId: Hex,
    public readonly requiredWei: bigint,
    public readonly availableWei: bigint,
    options?: PaymasterSdkErrorOptions,
  ) {
    super(
      `tenant ${tenantId} needs ${formatEther(requiredWei)} ETH but holds ${formatEther(availableWei)} ETH.`,
      options,
    );
  }
}

/** The fee collector is capped at what has accrued — that cap is what keeps tenant funds unreachable. */
export class ExceedsTreasuryError extends PaymasterSdkError {
  constructor(
    public readonly requestedWei: bigint,
    public readonly availableWei: bigint,
    options?: PaymasterSdkErrorOptions,
  ) {
    super(
      `cannot withdraw ${formatEther(requestedWei)} ETH: only ${formatEther(availableWei)} ETH has accrued to the treasury. ` +
        'The cap is deliberate — without it this path would reach tenant funds.',
      options,
    );
  }
}

export class PaymasterPausedError extends PaymasterSdkError {
  constructor(options?: PaymasterSdkErrorOptions) {
    super('the paymaster is paused, so it is not accepting new sponsorships. Withdrawals still work — a pause must not trap funds.', options);
  }
}

/** A revert the SDK recognised but has no dedicated class for. */
export class PaymasterRevertError extends PaymasterSdkError {
  constructor(
    public readonly errorName: string,
    public readonly args: readonly unknown[],
    operation: string,
    options?: PaymasterSdkErrorOptions,
  ) {
    super(`${operation} reverted with ${errorName}${args.length > 0 ? `(${args.map(String).join(', ')})` : '()'}`, options);
  }
}

/** Names the SDK knows how to spell out. Kept beside the classes so the two cannot drift. */
export type RoleNameLookup = (role: Hex) => string | undefined;

export type TranslateContext = {
  /** Human description of what was attempted, e.g. `register tenant 0x…`. */
  operation: string;
  /** The account that sent the call, when known. */
  account?: Address;
  /** Resolves a role hash to its name, so `MissingRoleError` can say `TENANT_ADMIN_ROLE`. */
  lookupRoleName?: RoleNameLookup;
};

/**
 * Turns a viem failure into the most specific SDK error available.
 *
 * Anything unrecognised is rethrown untouched rather than wrapped in a vaguer message: losing a
 * transport error's detail behind "operation failed" would make real outages harder to diagnose,
 * not easier.
 */
export function translateContractError(error: unknown, context: TranslateContext): unknown {
  if (!(error instanceof BaseError)) return error;

  const reverted = error.walk((candidate) => candidate instanceof ContractFunctionRevertedError);
  if (!(reverted instanceof ContractFunctionRevertedError)) return error;

  const name = reverted.data?.errorName;
  const args = (reverted.data?.args ?? []) as readonly unknown[];
  const cause = { cause: error };

  switch (name) {
    case 'AccessControlUnauthorizedAccount': {
      const [account, role] = args as [Address, Hex];
      return new MissingRoleError(account ?? context.account ?? '0x', role, context.lookupRoleName?.(role), context.operation, cause);
    }
    case 'NotWithdrawAddress': {
      const [tenantId, caller] = args as [Hex, Address];
      return new NotWithdrawAddressError(tenantId, caller, cause);
    }
    case 'UnknownTenant':
      return new UnknownTenantError(args[0] as Hex, cause);
    case 'TenantAlreadyRegistered':
      return new TenantAlreadyRegisteredError(args[0] as Hex, cause);
    case 'TenantInDeficit': {
      const [tenantId, deficit] = args as [Hex, bigint];
      return new TenantInDeficitError(tenantId, deficit, cause);
    }
    case 'InsufficientTenantBalance': {
      const [tenantId, required, available] = args as [Hex, bigint, bigint];
      return new InsufficientTenantBalanceError(tenantId, required, available, cause);
    }
    case 'ExceedsTreasury': {
      const [requested, available] = args as [bigint, bigint];
      return new ExceedsTreasuryError(requested, available, cause);
    }
    case 'PaymasterPaused':
    case 'EnforcedPause':
      return new PaymasterPausedError(cause);
    case 'TenantDisabled':
      return new PaymasterRevertError('TenantDisabled', args, context.operation, cause);
    case undefined:
      return error;
    default:
      return new PaymasterRevertError(name, args, context.operation, cause);
  }
}
