import type { PaymasterWalletClient } from '@appliedblockchain/giano-paymaster-sdk';
import { createPublicClient, createWalletClient, custom, defineChain, http, type Address, type Chain, type EIP1193Provider } from 'viem';
import type { Deployment } from '../config';
import { describeError } from './errors';

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
    name: deployment.name ?? `chain-${deployment.chainId}`,
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
 * The wallet is on a chain this console does not administer.
 *
 * A distinct type rather than a message, because the caller has something to offer: the console
 * knows which chain it wants and can ask the wallet to move to it. Anything else that fails during
 * connection is a plain error with nothing to do about it but read.
 */
export class ChainMismatchError extends Error {
  readonly walletChainId: number;
  readonly deployment: Deployment;

  constructor(walletChainId: number, deployment: Deployment) {
    super(`The wallet is on chain ${walletChainId}, but this console administers ${deployment.name} (chain ${deployment.chainId}).`);
    this.name = 'ChainMismatchError';
    this.walletChainId = walletChainId;
    this.deployment = deployment;
  }
}

/**
 * The wallet does not know this chain and would not take it from the console.
 *
 * Common and not a malfunction: hardware and custody wallets do not accept networks from a web
 * page at all, and MetaMask rejects any RPC URL that is not HTTPS or literal localhost — which a
 * console proxying its node through its own origin will routinely hand it. Carries what the
 * operator needs to add the network themselves, since that is the only way through.
 */
export class ChainNotAddedError extends Error {
  readonly deployment: Deployment;
  readonly rpcUrl: string;
  /** What the wallet said, verbatim. Its own words are usually more specific than anything here. */
  readonly walletMessage: string;

  constructor(deployment: Deployment, rpcUrl: string, cause: unknown) {
    super(`This wallet would not add ${deployment.name} (chain ${deployment.chainId}).`);
    this.name = 'ChainNotAddedError';
    this.deployment = deployment;
    this.rpcUrl = rpcUrl;
    this.walletMessage = describeError(cause);
  }
}

/** EIP-1193: the wallet does not know this chain and cannot switch to it until it is added. */
const UNRECOGNISED_CHAIN = 4902;

/** EIP-1193: the user declined the prompt. */
const USER_REJECTED = 4001;

function providerErrorCode(error: unknown): number | undefined {
  const code = (error as { code?: unknown })?.code;
  return typeof code === 'number' ? code : undefined;
}

function toHex(value: number): `0x${string}` {
  return `0x${value.toString(16)}`;
}

/**
 * Asks the wallet to move to the deployment's chain, adding it first if the wallet has never seen
 * it.
 *
 * The switch is still deliberate — the wallet raises its own prompt naming the network, and the
 * console only ever asks for a chain an operator explicitly selected from the configured list. So
 * a treasury withdrawal cannot end up signed against the wrong deployment by accident, while an
 * operator whose wallet happens to be on some other network is not left with a dead end.
 *
 * Adding is attempted only on 4902, and is the part most likely to fail — see
 * {@link ChainNotAddedError}, which the caller turns into instructions rather than an error.
 */
export async function switchChain(deployment: Deployment): Promise<void> {
  const provider = getInjectedProvider();
  if (!provider) throw new Error('No injected wallet found.');

  const chainId = toHex(deployment.chainId);

  try {
    await provider.request({ method: 'wallet_switchEthereumChain', params: [{ chainId }] });
    return;
  } catch (cause) {
    if (providerErrorCode(cause) !== UNRECOGNISED_CHAIN) throw cause;
  }

  // Where the WALLET should dial, which is not always where the console reads: `rpcUrl` is
  // routinely a path on this origin, proxying a node whose real address the browser is not meant
  // to hold. `walletRpcUrl` is the address to publish when there is one. Absolute either way — the
  // wallet is a different context entirely, with nothing to resolve a relative URL against.
  const rpcUrl = new URL(deployment.walletRpcUrl ?? deployment.rpcUrl, window.location.origin).toString();

  try {
    await provider.request({
      method: 'wallet_addEthereumChain',
      params: [
        {
          chainId,
          chainName: deployment.name,
          rpcUrls: [rpcUrl],
          nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
        },
      ],
    });

    // Some wallets add without switching; others switch as part of adding and no-op here.
    await provider.request({ method: 'wallet_switchEthereumChain', params: [{ chainId }] });
  } catch (cause) {
    if (isUserRejection(cause)) throw cause;
    throw new ChainNotAddedError(deployment, rpcUrl, cause);
  }
}

/** The deployment's chain as a wallet's "add a network" form asks for it. */
export function networkDetails(deployment: Deployment, rpcUrl: string) {
  return [
    { label: 'Network name', value: deployment.name },
    { label: 'Chain ID', value: String(deployment.chainId) },
    { label: 'RPC URL', value: rpcUrl },
    { label: 'Currency symbol', value: 'ETH' },
  ];
}

export function isUserRejection(error: unknown): boolean {
  return providerErrorCode(error) === USER_REJECTED;
}

/**
 * Prompts the injected wallet for an account and binds a wallet client to it.
 *
 * The chain is checked rather than silently switched: an admin console that quietly moved a
 * hardware wallet to another network would be a good way to sign a treasury withdrawal against
 * the wrong deployment. A mismatch comes back as {@link ChainMismatchError} so the caller can
 * offer {@link switchChain} as a deliberate second step.
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
    throw new ChainMismatchError(walletChainId, deployment);
  }

  const walletClient = createWalletClient({ account: address, chain: toChain(deployment), transport: custom(provider) });
  return { address, walletClient };
}

/**
 * Connects, moving the wallet onto this deployment's chain when it is somewhere else.
 *
 * The move is not silent even though nothing in the console asks for it: the wallet raises its own
 * prompt naming the network, and the console only ever asks for a chain an operator selected from
 * the configured list. So an operator cannot end up signing against a deployment they did not
 * choose, and one whose wallet simply happens to be elsewhere is not made to do anything about it.
 */
export async function connectOnChain(deployment: Deployment): Promise<ConnectedWallet> {
  try {
    return await connectWallet(deployment);
  } catch (cause) {
    if (!(cause instanceof ChainMismatchError)) throw cause;
  }

  await switchChain(deployment);
  return connectWallet(deployment);
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
