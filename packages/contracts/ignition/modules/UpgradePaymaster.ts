import { buildModule } from '@nomicfoundation/hardhat-ignition/modules';

/**
 * Deploys the current paymaster implementation and upgrades an existing UUPS proxy.
 * The transaction sender must hold UPGRADER_ROLE on that proxy. No initializer is
 * called: this upgrade preserves the proxy's roles, tenant balances and signers.
 */
export default buildModule('UpgradePaymaster', (m) => {
  const proxyAddress = m.getParameter('proxyAddress');
  const proxy = m.contractAt('GianoPaymaster', proxyAddress, { id: 'ExistingPaymaster' });
  // Check that the supplied address exposes the paymaster interface before deploying.
  const entryPoint = m.staticCall(proxy, 'entryPoint');
  const implementation = m.contract('GianoPaymaster', [], { after: [entryPoint] });
  const upgrade = m.call(proxy, 'upgradeToAndCall', [implementation, '0x']);
  // An EOA/no-op destination cannot masquerade as a successful upgrade.
  m.readEventArgument(upgrade, 'Upgraded', 'implementation');

  return { implementation, proxy };
});
