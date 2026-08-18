import { describe, expect, it } from 'vitest';
import { DEFAULT_ADMIN_ROLE, PAYMASTER_ROLES, PAYMASTER_ROLE_NAMES, ROLE_DESCRIPTIONS, roleName } from '../src/roles';

/**
 * The role hashes are computed client-side to save a round-trip per role, which is only safe while
 * they match the constants the contract actually compiles. These literals were taken from the
 * contract itself (`cast keccak "giano.paymaster.<ROLE>"`), so if anyone edits a role string in
 * `GianoPaymaster.sol` this fails here rather than at an authorisation check that silently
 * addresses a role nobody holds.
 */
const ON_CHAIN_ROLE_HASHES = {
  ROLE_ADMIN: '0x996fe4d14dba528d680563ba54f974644f00e51e77bfee7484d86a63102daa8b',
  SIGNER_ADMIN_ROLE: '0xbc580aa3dc613ccbcec128e1841ace0e62e0cbb5176aa05b5df2d51435073d24',
  FEE_ADMIN_ROLE: '0xd18d30c14b25f23dcc0ad7828c9220c6427ed8c75793eba42aa886e0547e1575',
  FEE_COLLECTOR_ROLE: '0xe2cb98f9ab8bcbc1ed3a7f8d246ef1976739073e8d104bc6bbe85c921a4ee83a',
  STAKE_ADMIN_ROLE: '0x8d86c4dcecd6f4dea2c1a19b7cbf464f1923f61835825feede704d624f5ac14c',
  TENANT_ADMIN_ROLE: '0x8fb1ef4148ad48f454517febd8f2389910d8ce34020838107d3679b007d92b49',
  PARAM_ADMIN_ROLE: '0x57679fcefb7fb679fea4abf8c99a74b6c4c3a84582e28f1262ba66cbbcbf2a29',
  PAUSER_ROLE: '0x65fb750f54de9b6ed469e7853ab195ae926c0f5883d4e00ef65f784819b22628',
  UPGRADER_ROLE: '0xa02f3509eff99e9e133af5b41e7ef81eab8a3dc12bce1aaf2c72228e275b694e',
} as const;

describe('role identifiers', () => {
  it.each(PAYMASTER_ROLE_NAMES)('computes %s to the hash the contract compiles', (name) => {
    expect(PAYMASTER_ROLES[name]).toBe(ON_CHAIN_ROLE_HASHES[name]);
  });

  it('covers every role the contract defines', () => {
    expect(PAYMASTER_ROLE_NAMES).toHaveLength(Object.keys(ON_CHAIN_ROLE_HASHES).length);
  });

  it('gives every role a distinct identifier', () => {
    const hashes = new Set(PAYMASTER_ROLE_NAMES.map((name) => PAYMASTER_ROLES[name]));
    expect(hashes.size).toBe(PAYMASTER_ROLE_NAMES.length);
  });

  it('never collides with DEFAULT_ADMIN_ROLE, which is deliberately never granted', () => {
    for (const name of PAYMASTER_ROLE_NAMES) {
      expect(PAYMASTER_ROLES[name]).not.toBe(DEFAULT_ADMIN_ROLE);
    }
  });
});

describe('roleName', () => {
  it('round-trips every known role', () => {
    for (const name of PAYMASTER_ROLE_NAMES) {
      expect(roleName(PAYMASTER_ROLES[name])).toBe(name);
    }
  });

  it('names the zero role', () => {
    expect(roleName(DEFAULT_ADMIN_ROLE)).toBe('DEFAULT_ADMIN_ROLE');
  });

  it('is case-insensitive, because nodes are inconsistent about topic casing', () => {
    expect(roleName(PAYMASTER_ROLES.PAUSER_ROLE.toUpperCase().replace('0X', '0x') as `0x${string}`)).toBe('PAUSER_ROLE');
  });

  it('returns undefined for a role it does not know rather than guessing', () => {
    expect(roleName('0xdead000000000000000000000000000000000000000000000000000000000000')).toBeUndefined();
  });
});

describe('role descriptions', () => {
  it('documents every role, both what it may and what it may not do', () => {
    for (const name of PAYMASTER_ROLE_NAMES) {
      const description = ROLE_DESCRIPTIONS[name];
      expect(description.name).toBe(name);
      expect(description.role).toBe(PAYMASTER_ROLES[name]);
      expect(description.may.length).toBeGreaterThan(0);
      expect(description.mayNot.length).toBeGreaterThan(0);
    }
  });
});
