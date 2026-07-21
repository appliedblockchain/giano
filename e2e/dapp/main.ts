import { createGianoWalletProvider, TransportRpcError } from '@appliedblockchain/giano-connector';
import { defineChain, http } from 'viem';

const chain = defineChain({
  id: Number(process.env.CHAIN_ID),
  name: 'e2e',
  nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
  rpcUrls: { default: { http: [process.env.RPC_URL as string] } },
});

const provider = createGianoWalletProvider({
  walletUrl: process.env.WALLET_URL as string,
  chain,
  transport: http(process.env.RPC_URL as string),
});

const out = document.getElementById('out')!;
const log = (label: string, value: unknown) => {
  out.textContent += `${label}: ${typeof value === 'string' ? value : JSON.stringify(value)}\n`;
};

declare global {
  interface Window {
    giano: { provider: typeof provider; log: typeof log };
  }
}
window.giano = { provider, log };

provider.on('accountsChanged', (accounts) => log('event:accountsChanged', accounts));
provider.on('disconnect', () => log('event:disconnect', ''));

document.getElementById('connect')!.addEventListener('click', async () => {
  try {
    const accounts = await provider.request<string[]>({ method: 'eth_requestAccounts' });
    log('accounts', accounts);
  } catch (error) {
    log('connect:error', error instanceof TransportRpcError ? `rpc:${error.code}` : (error as Error).message);
  }
});

document.getElementById('send')!.addEventListener('click', async () => {
  try {
    const [account] = await provider.request<string[]>({ method: 'eth_accounts' });
    const hash = await provider.request<string>({
      method: 'eth_sendTransaction',
      params: [{ to: account, value: '0x0' }],
    });
    log('userOpHash', hash);
    const receipt = await provider.request<{ success: boolean }>({ method: 'waitForUserOperationReceipt', params: [hash] });
    log('receipt:success', receipt.success);
  } catch (error) {
    log('send:error', error instanceof TransportRpcError ? `rpc:${error.code}` : (error as Error).message);
  }
});

document.getElementById('sign')!.addEventListener('click', async () => {
  try {
    const [account] = await provider.request<string[]>({ method: 'eth_accounts' });
    const signature = await provider.request<string>({
      method: 'personal_sign',
      params: [`0x${Array.from(new TextEncoder().encode('giano e2e'), (b) => b.toString(16).padStart(2, '0')).join('')}`, account],
    });
    log('signature', `len=${signature.length} ${signature.slice(0, 20)}…`);
  } catch (error) {
    log('sign:error', error instanceof TransportRpcError ? `rpc:${error.code}` : (error as Error).message);
  }
});

document.getElementById('sign-typed')!.addEventListener('click', async () => {
  try {
    const [account] = await provider.request<string[]>({ method: 'eth_accounts' });
    const typedData = JSON.stringify({
      domain: { name: 'E2E', version: '1', chainId: chain.id },
      types: { Greeting: [{ name: 'text', type: 'string' }] },
      primaryType: 'Greeting',
      message: { text: 'hello giano' },
    });
    const signature = await provider.request<string>({ method: 'eth_signTypedData_v4', params: [account, typedData] });
    log('typedSignature', `len=${signature.length} ${signature.slice(0, 20)}…`);
  } catch (error) {
    log('signTyped:error', error instanceof TransportRpcError ? `rpc:${error.code}` : (error as Error).message);
  }
});

document.getElementById('disconnect')!.addEventListener('click', () => {
  provider.disconnect();
  log('disconnected', '');
});
