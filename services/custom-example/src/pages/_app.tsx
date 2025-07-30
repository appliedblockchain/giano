import '../styles/globals.css';
import '@rainbow-me/rainbowkit/styles.css';
import type { AppProps } from 'next/app';

// Import our dynamic wagmi provider instead of static components
import { DynamicWagmiProvider } from '../providers/WagmiProvider';
// import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
// import { WagmiProvider } from 'wagmi';
// import { RainbowKitProvider } from '@rainbow-me/rainbowkit';

// import { config } from '../wagmi';

// const client = new QueryClient();

function MyApp({ Component, pageProps }: AppProps) {
  return (
    <DynamicWagmiProvider>
      {/* <RainbowKitProvider> */}
        <Component {...pageProps} />
      {/* </RainbowKitProvider> */}
    </DynamicWagmiProvider>
  );
}

export default MyApp;
