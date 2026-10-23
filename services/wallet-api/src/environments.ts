/**
 * Every environment wallet-api runs in, keyed by GIANO_ENVIRONMENT — the one piece of deployment
 * identity the image cannot know by itself. What an environment IS lives here, in code, so changing
 * it is a reviewed release rather than an edited variable (specs/OPERATOR-ADMIN-SPECS.md §4.1).
 *
 * - `siweDomain` / `siweUri`: what every operator sign-in message carries — the paymaster console's
 *   host, which DNS and Terraform decide. `null` means the environment runs no console, and no
 *   operator route is registered. Never stored in the database: a wrong value would sign every
 *   operator out, including whoever set it.
 * - `bootstrapOperators`: written by the init step (src/init.ts) ONLY into an operators table that
 *   is empty. After that the table belongs to the operators, who manage it in the console; a later
 *   release changing this list changes nothing in a database that has an operator. Addresses are
 *   public, so committing them is safe — what matters is who holds the keys.
 * - `localStack`: a compose stack on a developer machine or in CI. Only these may load tenant
 *   fixtures, so no live configuration can create a tenant.
 */

export type OperatorSeed = { id: string; address: `0x${string}` };

export type Environment = {
  siweDomain: string | null;
  /** Defaults to https://<siweDomain>. */
  siweUri?: string;
  bootstrapOperators: readonly OperatorSeed[];
  localStack: boolean;
};

const GIOVANNI: OperatorSeed = { id: 'giovanni', address: '0xFebBB1e5b6D66E6281d0d4d4816f76B69365a09d' };
/** anvil's account 0: holds every devnet paymaster role, and is the console's injected e2e wallet. */
const ANVIL_0: OperatorSeed = { id: 'ops-console', address: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266' };
/** anvil's account 3: holds no paymaster role; signs in from e2e/tests/operator.spec.ts. */
const ANVIL_3: OperatorSeed = { id: 'ops-e2e', address: '0x90F79bf6EB2c4f870365E785982E1f101E93b906' };

export const ENVIRONMENTS = {
  // ── Live (infra/iac workspaces) ─────────────────────────────────────────────────────────────
  // The hosts are infra/iac's `paymaster.<dns_prefix>.<dns_zone>`; prd's zone is expected to change.
  dev: { siweDomain: 'paymaster.dev.giano.appliedblockchain.dev', bootstrapOperators: [GIOVANNI], localStack: false },
  stg: { siweDomain: 'paymaster.stg.giano.appliedblockchain.dev', bootstrapOperators: [GIOVANNI], localStack: false },
  prd: { siweDomain: 'paymaster.giano.appliedblockchain.dev', bootstrapOperators: [GIOVANNI], localStack: false },
  // A client-run deployment from deploy/docker-compose.reference.yml: no console of Giano's.
  reference: { siweDomain: null, bootstrapOperators: [], localStack: false },

  // ── Local stacks (deploy/docker-compose.*.yml) ───────────────────────────────────────────────
  e2e: { siweDomain: 'paymaster.localhost', siweUri: 'http://paymaster.localhost', bootstrapOperators: [ANVIL_3, ANVIL_0, GIOVANNI], localStack: true },
  'local-infra': {
    siweDomain: 'paymaster.giano.localhost',
    siweUri: 'http://paymaster.giano.localhost',
    bootstrapOperators: [ANVIL_0, GIOVANNI],
    localStack: true,
  },
  // docker-compose.dev.yml and docker-compose.sepolia.yml run no console
  'local-dev': { siweDomain: null, bootstrapOperators: [GIOVANNI], localStack: true },
  'local-sepolia': { siweDomain: null, bootstrapOperators: [GIOVANNI], localStack: true },
  // the wallet-api test suite; its operators are written by the suite itself
  test: { siweDomain: 'paymaster.localhost', siweUri: 'http://paymaster.localhost', bootstrapOperators: [], localStack: true },
} as const satisfies Record<string, Environment>;

export type EnvironmentName = keyof typeof ENVIRONMENTS;
export const ENVIRONMENT_NAMES = Object.keys(ENVIRONMENTS) as [EnvironmentName, ...EnvironmentName[]];

export type ResolvedEnvironment = Omit<Environment, 'siweUri'> & { name: EnvironmentName; siweUri: string | null };

/** The environment named by GIANO_ENVIRONMENT, with its sign-in URI resolved. Throws on an unknown name. */
export function resolveEnvironment(name: string | undefined): ResolvedEnvironment {
  if (!name || !(name in ENVIRONMENTS)) {
    throw new Error(`GIANO_ENVIRONMENT must be one of ${ENVIRONMENT_NAMES.join(', ')} (got ${name ? `"${name}"` : 'nothing'})`);
  }
  const environment: Environment = ENVIRONMENTS[name as EnvironmentName];
  const siweUri = environment.siweDomain ? (environment.siweUri ?? `https://${environment.siweDomain}`) : null;
  return { ...environment, name: name as EnvironmentName, siweUri };
}
