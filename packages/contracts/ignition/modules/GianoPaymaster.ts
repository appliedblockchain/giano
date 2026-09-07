import { buildModule } from '@nomicfoundation/hardhat-ignition/modules';

/**
 * Deploys the production sponsorship paymaster.
 *
 * Three artifacts, and the order matters:
 *
 *   1. `GianoPaymaster`         — the implementation. No constructor arguments, so its bytecode
 *                                 (and therefore its CREATE2 address) is identical for every
 *                                 operator.
 *   2. `GianoPaymasterDeployer` — deploys the proxy and initialises it in one transaction.
 *   3. the proxy                — a stock `ERC1967Proxy` with an *empty* initialisation payload.
 *
 * The empty payload is what keeps the address stable: passing initialiser calldata to the proxy
 * constructor, the usual OpenZeppelin pattern, would bake the operator's own role-admin address
 * into the init code. The gap that leaves between deploying and initialising is closed by doing
 * both inside `GianoPaymasterDeployer.deploy`, not by a custom proxy.
 *
 * Roles, stake, tenant registration and funding are deliberately *not* here. They are
 * operator-specific and, in production, go through the timelock — see
 * `scripts/provision-paymaster.ts` for the scripted form the devnet and e2e stacks use.
 *
 * Kept out of `index.ts` and out of `Testing.ts`: the production paymaster and the permissive test
 * paymaster must never be reachable from the same deployment target.
 */

/** The repo's fixed CREATE2 salt, matching `hardhat.config.ts`'s Ignition strategy config. */
const DEPLOY_SALT = '0xAB000000000000000000000000000000000000000000000000000000000000AB';

const ENTRY_POINT_V07 = '0x0000000071727De22E5E9d8BAf0edAc6f37da032';

export default buildModule('GianoPaymaster', (m) => {
  // The sole ROLE_ADMIN holder. In production this is a TimelockController whose proposers are a
  // Safe; the default is the first Hardhat/anvil account so a local devnet stands itself up.
  const roleAdmin = m.getParameter('roleAdmin', m.getAccount(0));
  const entryPoint = m.getParameter('entryPoint', ENTRY_POINT_V07);

  // Deployment-wide platform fee per sponsored operation, in wei.
  const defaultFeeWei = m.getParameter('defaultFeeWei', 100_000_000_000_000n); // 0.0001 ETH
  // Gas units charged for the settlement step's own gas. Measured at ~9.7k warm and ~49k cold in
  // `test/GianoPaymaster/Gas.t.sol`; calibrate per chain before the first tenant funds.
  const postOpGasAllowance = m.getParameter('postOpGasAllowance', 40_000);
  // Basis points of the execution gas limits charged as a bound on the EntryPoint's penalty on
  // unused gas. 1000 = its 10%.
  const penaltyBps = m.getParameter('penaltyBps', 1000);

  const implementation = m.contract('GianoPaymaster');
  const deployer = m.contract('GianoPaymasterDeployer');

  const initCalldata = m.encodeFunctionCall(implementation, 'initialize', [
    entryPoint,
    roleAdmin,
    defaultFeeWei,
    postOpGasAllowance,
    penaltyBps,
  ]);

  // `predict` is a pure function of (deployer, salt, implementation) — the same inputs `deploy`
  // uses — so resolving the address before the call is safe and lets the registry record it.
  const proxyAddress = m.staticCall(deployer, 'predict', [DEPLOY_SALT, implementation]);
  const deployCall = m.call(deployer, 'deploy', [DEPLOY_SALT, implementation, initCalldata]);

  const sponsorshipPaymaster = m.contractAt('GianoPaymaster', proxyAddress, {
    id: 'SponsorshipPaymaster',
    after: [deployCall],
  });

  return { implementation, deployer, sponsorshipPaymaster };
});
