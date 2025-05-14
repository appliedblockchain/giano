import { type EIP1193EventMap, type EIP1193Provider, type EIP1193RequestFn, getContract, getContract } from 'viem';

// Check: https://github.com/coinbase/coinbase-wallet-sdk/blob/296075530ad1f2f955c793c04ebba310277d1904/packages/wallet-sdk/src/CoinbaseWalletProvider.ts#L22
const AccountFactoryAddress = '0x811BccaEF5AB2dB5857c32D70a2cfd16A45178f4';

export function createGianoEIP1193Provider(): EIP1193Provider {
  return {
    on: <event extends keyof EIP1193EventMap>(event: event, listener: EIP1193EventMap[event]) => {
      // Implementation will be added later
      return undefined;
    },
    removeListener: <event extends keyof EIP1193EventMap>(event: event, listener: EIP1193EventMap[event]) => {
      // Implementation will be added later
      return undefined;
    },
    request: (async ({ method, params }) => {
      switch (method) {
        case 'eth_sendTransaction':
          break;
        case 'personal_sign':
          break;
        case 'eth_signTypedData_v4':
          break;
        // https://eips.ethereum.org/EIPS/eip-1102
        case 'eth_requestAccounts':
          break;
        // https://eips.ethereum.org/EIPS/eip-1193
        case 'eth_accounts':
          break;
        // https://eips.ethereum.org/EIPS/eip-3326
        case 'wallet_switchEthereumChain':
          break;
        // https://eips.ethereum.org/EIPS/eip-2255
        case 'wallet_getPermissions':
          break;
        case 'wallet_requestPermissions':
          break;
      }
    }) as EIP1193RequestFn,
  };
}
