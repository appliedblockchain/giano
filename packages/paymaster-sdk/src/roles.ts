import { keccak256, toBytes, type Hex } from 'viem';

/**
 * The role topology.
 *
 * There is no owner and no superuser on this paymaster. Every privileged action is gated by its
 * own role, every role's admin is `ROLE_ADMIN` (which in a real deployment is a timelock), and
 * `DEFAULT_ADMIN_ROLE` is never granted. That separation is the whole point of the design, so the
 * SDK carries it as data rather than leaving each caller to hard-code hashes: an admin UI can then
 * render *why* an account may do a thing, not just whether the call reverted.
 *
 * The hashes are computed here rather than read from the chain. They are compile-time constants of
 * the contract, so a round-trip per role would be latency for nothing — and `test/roles.test.ts`
 * pins every value against the constants `forge` reports, so a drift is a failing test rather than
 * an authorisation check that silently addresses a role nobody holds.
 */

/** Every role the paymaster defines, plus the OpenZeppelin default that is deliberately unused. */
export const PAYMASTER_ROLE_NAMES = [
  'ROLE_ADMIN',
  'SIGNER_ADMIN_ROLE',
  'FEE_ADMIN_ROLE',
  'FEE_COLLECTOR_ROLE',
  'STAKE_ADMIN_ROLE',
  'TENANT_ADMIN_ROLE',
  'PARAM_ADMIN_ROLE',
  'PAUSER_ROLE',
  'UPGRADER_ROLE',
] as const;

export type PaymasterRoleName = (typeof PAYMASTER_ROLE_NAMES)[number];

/** `DEFAULT_ADMIN_ROLE`. Never granted — a holder would be a superuser by another name. */
export const DEFAULT_ADMIN_ROLE: Hex = '0x0000000000000000000000000000000000000000000000000000000000000000';

const hashRole = (name: PaymasterRoleName): Hex => keccak256(toBytes(`giano.paymaster.${name}`));

/** Role name → its `bytes32` identifier. */
export const PAYMASTER_ROLES: Record<PaymasterRoleName, Hex> = Object.fromEntries(
  PAYMASTER_ROLE_NAMES.map((name) => [name, hashRole(name)]),
) as Record<PaymasterRoleName, Hex>;

const NAME_BY_HASH: ReadonlyMap<Hex, PaymasterRoleName> = new Map(
  PAYMASTER_ROLE_NAMES.map((name) => [PAYMASTER_ROLES[name], name] as const),
);

/** Resolves a role hash to its name, or `undefined` for a hash this package does not know. */
export function roleName(role: Hex): PaymasterRoleName | 'DEFAULT_ADMIN_ROLE' | undefined {
  if (role.toLowerCase() === DEFAULT_ADMIN_ROLE) return 'DEFAULT_ADMIN_ROLE';
  return NAME_BY_HASH.get(role.toLowerCase() as Hex);
}

export type RoleDescription = {
  name: PaymasterRoleName;
  role: Hex;
  /** What holding it lets an account do. */
  may: string;
  /** The bound that matters — what it deliberately cannot do. Half the design lives here. */
  mayNot: string;
};

/**
 * What each role is for, in the contract's own terms.
 *
 * The `mayNot` half is not decoration: the security argument is a set of pairs (the fee admin
 * cannot collect the fees it sets; the fee collector cannot change the rate; no role at all can
 * reach a tenant's balance), and an operator reviewing role holders needs to see the pair.
 */
export const ROLE_DESCRIPTIONS: Record<PaymasterRoleName, RoleDescription> = {
  ROLE_ADMIN: {
    name: 'ROLE_ADMIN',
    role: PAYMASTER_ROLES.ROLE_ADMIN,
    may: 'grant and revoke every role, including itself',
    mayNot: 'move funds, or act on any other role directly. Held by the timelock in production',
  },
  SIGNER_ADMIN_ROLE: {
    name: 'SIGNER_ADMIN_ROLE',
    role: PAYMASTER_ROLES.SIGNER_ADMIN_ROLE,
    may: 'add and revoke sponsorship signing keys',
    mayNot: 'move funds',
  },
  FEE_ADMIN_ROLE: {
    name: 'FEE_ADMIN_ROLE',
    role: PAYMASTER_ROLES.FEE_ADMIN_ROLE,
    may: 'set the platform fee and per-tenant overrides',
    mayNot: 'collect the fees it sets',
  },
  FEE_COLLECTOR_ROLE: {
    name: 'FEE_COLLECTOR_ROLE',
    role: PAYMASTER_ROLES.FEE_COLLECTOR_ROLE,
    may: 'withdraw accrued treasury, capped at what has accrued',
    mayNot: 'change the fee rate, or reach tenant balances — the cap is what guarantees that',
  },
  STAKE_ADMIN_ROLE: {
    name: 'STAKE_ADMIN_ROLE',
    role: PAYMASTER_ROLES.STAKE_ADMIN_ROLE,
    may: 'add, unlock and withdraw the EntryPoint stake',
    mayNot: 'touch the deposit',
  },
  TENANT_ADMIN_ROLE: {
    name: 'TENANT_ADMIN_ROLE',
    role: PAYMASTER_ROLES.TENANT_ADMIN_ROLE,
    may: 'register tenants, enable and disable them, and set their withdrawal addresses',
    mayNot: 'move their funds',
  },
  PARAM_ADMIN_ROLE: {
    name: 'PARAM_ADMIN_ROLE',
    role: PAYMASTER_ROLES.PARAM_ADMIN_ROLE,
    may: 'set the overhead allowance and the penalty basis points',
    mayNot: 'move funds',
  },
  PAUSER_ROLE: {
    name: 'PAUSER_ROLE',
    role: PAYMASTER_ROLES.PAUSER_ROLE,
    may: 'halt acceptance of new sponsorships',
    mayNot: 'move funds or alter configuration. Withdrawals keep working while paused',
  },
  UPGRADER_ROLE: {
    name: 'UPGRADER_ROLE',
    role: PAYMASTER_ROLES.UPGRADER_ROLE,
    may: 'replace the implementation',
    mayNot: 'be held by anything but the timelock — this is the one power that can override custody',
  },
};
