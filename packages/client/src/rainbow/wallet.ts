import type { Wallet } from '@rainbow-me/rainbowkit';
import { getWalletConnectConnector } from '@rainbow-me/rainbowkit';
import { createGianoConnector } from '../wagmi/connector';
export type MyWalletOptions = {
  projectId: string;
};
export const rainbow = ({ projectId }: MyWalletOptions): Wallet => ({
  id: 'giano',
  name: 'Giano',
  iconUrl: 'https://my-image.xyz',
  iconBackground: '#0c2f78',
  //   downloadUrls: {
  //     android: 'https://play.google.com/store/apps/details?id=my.wallet',
  //     ios: 'https://apps.apple.com/us/app/my-wallet',
  //     chrome: 'https://chrome.google.com/webstore/detail/my-wallet',
  //     qrCode: 'https://my-wallet/qr',
  //   },
  mobile: {
    getUri: (uri: string) => uri,
  },
  qrCode: {
    getUri: (uri: string) => uri,
    instructions: {
      learnMoreUrl: 'https://my-wallet/learn-more',
      steps: [
        {
          description: 'We recommend putting My Wallet on your home screen for faster access to your wallet.',
          step: 'install',
          title: 'Open the My Wallet app',
        },
        {
          description: 'After you scan, a connection prompt will appear for you to connect your wallet.',
          step: 'scan',
          title: 'Tap the scan button',
        },
      ],
    },
  },
  createConnector: (walletDetails) => {
    return createGianoConnector;
  },
});
