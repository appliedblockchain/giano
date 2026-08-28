import { createGianoWalletProvider, TransportRpcError, UnsupportedChainError } from '@appliedblockchain/giano-connector';
import { defineChain, http } from 'viem';

const chain = defineChain({
  id: Number(process.env.CHAIN_ID),
  name: 'e2e',
  nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
  rpcUrls: { default: { http: [process.env.RPC_URL as string] } },
});

const chainB = defineChain({
  id: Number(process.env.CHAIN_B_ID),
  name: 'e2e-b',
  nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
  rpcUrls: { default: { http: [process.env.RPC_B_URL as string] } },
});

const provider = createGianoWalletProvider({
  walletUrl: process.env.WALLET_URL as string,
  chain,
  transport: http(process.env.RPC_URL as string),
});

// TWO providers over the SAME wallet URL, one per chain — the real mechanism (MC-10, MC-122):
// providerB negotiates chain B in its own handshake and holds its own session cache.
const providerB = createGianoWalletProvider({
  walletUrl: process.env.WALLET_URL as string,
  chain: chainB,
  transport: http(process.env.RPC_B_URL as string),
});

const out = document.getElementById('out')!;
const log = (label: string, value: unknown) => {
  out.textContent += `${label}: ${typeof value === 'string' ? value : JSON.stringify(value)}\n`;
};

declare global {
  interface Window {
    giano: { provider: typeof provider; providerB: typeof providerB; log: typeof log };
  }
}
window.giano = { provider, providerB, log };

provider.on('accountsChanged', (accounts) => log('event:accountsChanged', accounts));
provider.on('disconnect', () => log('event:disconnect', ''));

document.getElementById('connect')!.addEventListener('click', async () => {
  try {
    const accounts = await provider.request<string[]>({ method: 'eth_requestAccounts' });
    log('accounts', accounts);
  } catch (error) {
    log('connect:error', error instanceof TransportRpcError ? `rpc:${error.code} ${error.message}` : (error as Error).message);
  }
});

/**
 * Sends 0 ETH to self through the given provider and reports, in the output surface, the
 * chain the transaction went to and the account used — so a test asserts both DIRECTLY
 * rather than inferring them (MC-123).
 */
async function sendToSelf(via: typeof provider, chainId: number) {
  const [account] = await via.request<string[]>({ method: 'eth_accounts' });
  const hash = await via.request<string>({
    method: 'eth_sendTransaction',
    params: [{ to: account, value: '0x0' }],
  });
  log('userOpHash', hash);
  const receipt = await via.request<{ success: boolean }>({ method: 'waitForUserOperationReceipt', params: [hash] });
  log('receipt:success', receipt.success);
  log('result', { action: 'send', chainId, account, userOpHash: hash, receiptSuccess: receipt.success });
}

document.getElementById('send')!.addEventListener('click', async () => {
  try {
    await sendToSelf(provider, chain.id);
  } catch (error) {
    log('send:error', error instanceof TransportRpcError ? `rpc:${error.code}` : (error as Error).message);
  }
});

document.getElementById('connect-chain-b')!.addEventListener('click', async () => {
  try {
    const accounts = await providerB.request<string[]>({ method: 'eth_requestAccounts' });
    log('accountsB', accounts);
  } catch (error) {
    log('connectB:error', error instanceof TransportRpcError ? `rpc:${error.code} ${error.message}` : (error as Error).message);
  }
});

document.getElementById('send-chain-b')!.addEventListener('click', async () => {
  try {
    await sendToSelf(providerB, chainB.id);
  } catch (error) {
    log('sendB:error', error instanceof TransportRpcError ? `rpc:${error.code}` : (error as Error).message);
  }
});

/** A chain the wallet origin does not serve: the connection itself must be refused (MC-109). */
document.getElementById('connect-unserved')!.addEventListener('click', async () => {
  const unserved = defineChain({
    id: 99_999,
    name: 'unserved',
    nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
    rpcUrls: { default: { http: [process.env.RPC_URL as string] } },
  });
  const doomed = createGianoWalletProvider({
    walletUrl: process.env.WALLET_URL as string,
    chain: unserved,
    transport: http(process.env.RPC_URL as string),
  });
  try {
    await doomed.request({ method: 'eth_requestAccounts' });
    log('unserved:error', 'connection unexpectedly SUCCEEDED');
  } catch (error) {
    if (error instanceof UnsupportedChainError) {
      log('unserved:refused', { code: error.code, requestedChainId: error.requestedChainId, supportedChainIds: error.supportedChainIds });
    } else {
      log('unserved:error', (error as Error).message);
    }
  }
});

/**
 * A transfer of the demo ERC-20 — an ordinary allow-listed contract call, which is what the
 * sponsored path looks like for a real application. `#send` is a self-call, which the sponsorship
 * rules classify as wallet management, so it cannot stand in for this.
 */
document.getElementById('send-erc20')!.addEventListener('click', async () => {
  try {
    const [account] = await provider.request<string[]>({ method: 'eth_accounts' });
    // transfer(address,uint256) — to self, 0 tokens: the call has to be valid, not meaningful.
    const data = `0xa9059cbb${account.slice(2).padStart(64, '0')}${'0'.repeat(64)}`;
    const hash = await provider.request<string>({
      method: 'eth_sendTransaction',
      params: [{ to: process.env.TEST_ERC20_ADDRESS as string, value: '0x0', data }],
    });
    log('userOpHash', hash);
    const receipt = await provider.request<{ success: boolean }>({ method: 'waitForUserOperationReceipt', params: [hash] });
    log('receipt:success', receipt.success);
  } catch (error) {
    log('send:error', error instanceof TransportRpcError ? `rpc:${error.code}` : (error as Error).message);
  }
});

/** A call to a contract no tenant allow-lists — the sponsorship refusal path. */
document.getElementById('send-unlisted')!.addEventListener('click', async () => {
  try {
    const hash = await provider.request<string>({
      method: 'eth_sendTransaction',
      params: [{ to: '0x000000000000000000000000000000000000dEaD', value: '0x0', data: '0xa9059cbb' }],
    });
    log('userOpHash', hash);
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
