import type { PaymasterWalletClient } from '@appliedblockchain/giano-paymaster-sdk';
import { createPublicClient, createWalletClient, custom, defineChain, http, type Address, type Chain, type EIP1193Provider } from 'viem';
import type { Deployment } from '../config';

/**
 * Chain wiring.
 *
 * Reads go over plain HTTP so the console is useful with no wallet at all — an operator checking
 * solvency or a tenant balance should not have to connect one, and most of the time nobody should.
 * Writes come from an injected EIP-1193 wallet, which is where the keys stay: the SDK is handed a
 * wallet client that can already sign and never sees the key. The role holders on a real
 * deployment are hardware wallets and timelocks, so this is the only shape that could work.
 */

export function toChain(deployment: Deployment): Chain {
  return defineChain({
    id: deployment.chainId,
    name: deployment.label ?? `chain-${deployment.chainId}`,
    nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
    rpcUrls: { default: { http: [deployment.rpcUrl] } },
  });
}

export function createReadClient(deployment: Deployment) {
  return createPublicClient({ chain: toChain(deployment), transport: http(deployment.rpcUrl) });
}

type InjectedProvider = EIP1193Provider & { isMetaMask?: boolean };

export function getInjectedProvider(): InjectedProvider | undefined {
  return (globalThis as { ethereum?: InjectedProvider }).ethereum;
}

export type ConnectedWallet = {
  address: Address;
  walletClient: PaymasterWalletClient;
};

/**
 * Prompts the injected wallet for an account and binds a wallet client to it.
 *
 * The chain is checked rather than silently switched: an admin console that quietly moved a
 * hardware wallet to another network would be a good way to sign a treasury withdrawal against
 * the wrong deployment. If it disagrees, the caller is told and asked to switch deliberately.
 */
export async function connectWallet(deployment: Deployment): Promise<ConnectedWallet> {
  const provider = getInjectedProvider();
  if (!provider) {
    throw new Error('No injected wallet found. Install a browser wallet, or use the console read-only.');
  }

  const accounts = (await provider.request({ method: 'eth_requestAccounts' })) as Address[];
  const address = accounts[0];
  if (!address) throw new Error('The wallet returned no account.');

  const walletChainId = Number(await provider.request({ method: 'eth_chainId' }));
  if (walletChainId !== deployment.chainId) {
    throw new Error(`The wallet is on chain ${walletChainId}, but this console administers chain ${deployment.chainId}. Switch networks and reconnect.`);
  }

  const walletClient = createWalletClient({ account: address, chain: toChain(deployment), transport: custom(provider) });
  return { address, walletClient };
}

/** Accounts the wallet has already authorised, without prompting. Used to restore a session. */
export async function getAuthorisedAccount(deployment: Deployment): Promise<ConnectedWallet | undefined> {
  const provider = getInjectedProvider();
  if (!provider) return undefined;

  const accounts = (await provider.request({ method: 'eth_accounts' })) as Address[];
  const address = accounts[0];
  if (!address) return undefined;

  const walletChainId = Number(await provider.request({ method: 'eth_chainId' }));
  if (walletChainId !== deployment.chainId) return undefined;

  return { address, walletClient: createWalletClient({ account: address, chain: toChain(deployment), transport: custom(provider) }) };
}
