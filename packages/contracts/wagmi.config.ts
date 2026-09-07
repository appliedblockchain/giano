import { defineConfig } from '@wagmi/cli';
import { hardhat } from '@wagmi/cli/plugins';

export default defineConfig({
  out: 'generated.ts',
  contracts: [],
  plugins: [
    hardhat({
      project: '.',
      // `UUPSUpgradeable` exists twice once the paymaster pulls in the OpenZeppelin *upgradeable*
      // package alongside Solady's, and the plugin requires unique contract names. Excluding the
      // base classes we never call directly is the fix; the concrete contracts keep their ABIs.
      exclude: ['@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol/**'],
    }),
  ],
});
