import { giano } from '@appliedblockchain/giano-connector';
import { createGianoProvider } from '@appliedblockchain/giano-connector';
import { hardhatDefaultAccountSender } from '@appliedblockchain/giano-connector';
import { connectorsForWallets } from '@rainbow-me/rainbowkit';
import { metaMaskWallet } from '@rainbow-me/rainbowkit/wallets';
import { custom, http } from 'viem';
import { createConfig } from 'wagmi';
import { hardhat } from 'wagmi/chains';

const rpcs = {
  chains: [hardhat],
  transports: {
    [hardhat.id]: http('http://localhost:8545/'),
  },
};

const provider = createGianoProvider({
  chains: rpcs.chains,
  transports: rpcs.transports,
  initialChainId: hardhat.id,
  sendTransaction: hardhatDefaultAccountSender,
});

const providerTransport = custom(provider);

const connectors = connectorsForWallets(
  [
    {
      groupName: 'Passkeys',
      wallets: [giano({ provider })],
    },
    { groupName: 'Test', wallets: [metaMaskWallet] },
  ],
  {
    appName: 'Rainbow Wallet',
    projectId: 'whatever',
  },
);

console.log(connectors);

export const config = createConfig({
  chains: [...rpcs.chains],
  transports: {
    ...Object.fromEntries(
      Object.keys(rpcs.transports).map((k) => {
        return [k, providerTransport];
      }),
    ),
  },
  connectors,
});
