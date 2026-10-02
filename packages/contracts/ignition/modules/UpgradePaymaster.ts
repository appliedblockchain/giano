import { buildModule } from '@nomicfoundation/hardhat-ignition/modules';

/**
 * Deploys the current paymaster implementation and upgrades an existing UUPS proxy.
 * The transaction sender must hold UPGRADER_ROLE on that proxy. No initializer is
 * called: this upgrade preserves the proxy's roles, tenant balances and signers.
 * The implementation uses the proxy's stored EntryPoint, including custom deployments;
 * upgrading does not replace it with the network's canonical EntryPoint.
 */
export default buildModule('UpgradePaymaster', (m) => {
  const proxyAddress = m.getParameter('proxyAddress');
  const proxy = m.contractAt('GianoPaymaster', proxyAddress, { id: 'ExistingPaymaster' });
  // Check the paymaster interface, not equality with a canonical EntryPoint: the
  // implementation accepts the existing proxy's configured IEntryPoint.
  const entryPoint = m.staticCall(proxy, 'entryPoint');
  const implementation = m.contract('GianoPaymaster', [], { after: [entryPoint] });
  const upgrade = m.call(proxy, 'upgradeToAndCall', [implementation, '0x']);
  // An EOA/no-op destination cannot masquerade as a successful upgrade.
  m.readEventArgument(upgrade, 'Upgraded', 'implementation');

  return { implementation, proxy };
});
