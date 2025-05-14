import { connectorsForWallets } from '@rainbow-me/rainbowkit';
import { metaMaskWallet } from '@rainbow-me/rainbowkit/wallets';
import { http } from 'viem';
import { createConfig } from 'wagmi';
import { hardhat } from 'wagmi/chains';
import { giano } from './gianoWallet';

const connectors = connectorsForWallets(
  [
    {
      groupName: 'Passkeys',
      wallets: [giano(hardhat.id)],
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
  chains: [hardhat],
  transports: {
    [hardhat.id]: http('http://localhost:8545/'),
  },
  connectors,
});
