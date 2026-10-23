import { expect, type Page } from '@playwright/test';

import { ORIGINS } from '../origins.mjs';

/**
 * The scripted browser wallet the paymaster console is driven with, shared by the console's
 * specs (paymaster-admin.spec.ts, platform-console.spec.ts).
 *
 * A real extension cannot be driven, so an EIP-1193 wallet is injected before any page script
 * runs, shaped like MetaMask where the console's behaviour depends on it. Its accounts are anvil's
 * own, unlocked on the devnet: anything it does not answer itself — eth_sendTransaction,
 * personal_sign — is forwarded through the console's same-origin /rpc/<chainId> proxy and signed
 * by the node.
 */

/** anvil's first account, which holds every role on the devnet paymaster. */
export const OPERATOR = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';

/** A chain neither devnet uses, so a connection always has to move the wallet. */
export const ELSEWHERE = '0x1';

export type WalletOptions = {
  /** Chains the wallet already knows. Anything else must go through `wallet_addEthereumChain`. */
  known?: number[];
  /** Make the wallet refuse to add a network, the way one that only holds fixed networks does. */
  refuseAdd?: boolean;
};

export type WalletCall = { method: string; params: unknown[] };

declare global {
  interface Window {
    __wallet: { calls: WalletCall[]; chainId: () => string };
  }
}

/**
 * Installs an EIP-1193 wallet before any page script runs.
 *
 * Modelled on MetaMask where the console's behaviour depends on it: 4902 for a chain it does not
 * know, MetaMask's HTTPS-or-localhost rule on the RPC URL of a network it is asked to add, and a
 * serialised `{ code, message }` object rather than an `Error` — which is what actually crosses an
 * extension boundary, and what the console has to read a reason out of.
 */
export async function installWallet(page: Page, { known = [], refuseAdd = false }: WalletOptions = {}) {
  await page.addInitScript(
    ({ operator, elsewhere, known, refuseAdd }) => {
      const knownChains = new Set(known.map((id) => `0x${id.toString(16)}`));
      const listeners: Record<string, ((payload: unknown) => void)[]> = {};
      const calls: { method: string; params: unknown[] }[] = [];
      let chainId = elsewhere;

      const emit = (event: string, payload: unknown) => (listeners[event] ?? []).forEach((fn) => fn(payload));

      const forward = async (method: string, params: unknown[]) => {
        const response = await fetch(`${location.origin}/rpc/${parseInt(chainId, 16)}`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', id: Date.now(), method, params }),
        });
        const body = await response.json();
        if (body.error) throw { code: body.error.code, message: body.error.message };
        return body.result;
      };

      const provider = {
        isMetaMask: true,
        async request({ method, params = [] }: { method: string; params?: unknown[] }) {
          calls.push({ method, params });
          switch (method) {
            case 'eth_requestAccounts':
            case 'eth_accounts':
              return [operator];
            case 'eth_chainId':
              return chainId;
            case 'wallet_switchEthereumChain': {
              const target = (params[0] as { chainId: string }).chainId;
              if (!knownChains.has(target)) throw { code: 4902, message: `Unrecognized chain ID ${target}.` };
              chainId = target;
              emit('chainChanged', target);
              return null;
            }
            case 'wallet_addEthereumChain': {
              const added = params[0] as { chainId: string; rpcUrls: string[] };
              if (refuseAdd) throw { code: -32601, message: 'this wallet does not add networks' };
              const url = new URL(added.rpcUrls[0]);
              if (url.protocol !== 'https:' && url.hostname !== 'localhost' && url.hostname !== '127.0.0.1') {
                throw {
                  code: -32602,
                  message: `Expected an array with at least one valid string HTTPS url 'rpcUrls', Received:\n${added.rpcUrls[0]}`,
                };
              }
              knownChains.add(added.chainId);
              return null;
            }
            default:
              return forward(method, params);
          }
        },
        on(event: string, fn: (payload: unknown) => void) {
          (listeners[event] ??= []).push(fn);
        },
        removeListener(event: string, fn: (payload: unknown) => void) {
          listeners[event] = (listeners[event] ?? []).filter((other) => other !== fn);
        },
      };

      Object.defineProperty(window, 'ethereum', { value: provider, writable: true, configurable: true });
      Object.defineProperty(window, '__wallet', { value: { calls, chainId: () => chainId }, writable: false, configurable: true });
    },
    { operator: OPERATOR, elsewhere: ELSEWHERE, known, refuseAdd },
  );
}

export const walletCalls = (page: Page) => page.evaluate(() => window.__wallet.calls.map((call) => call.method));
export const walletChain = (page: Page) => page.evaluate(() => window.__wallet.chainId());

/** Picks a deployment in the header, which the console offers only when it administers several. */
export async function chooseDeployment(page: Page, chainId: number) {
  const picker = page.getByLabel('Deployment');
  const value = await picker.evaluate((element, wanted) => {
    const option = [...(element as HTMLSelectElement).options].find((candidate) => candidate.textContent?.includes(`chain ${wanted}`));
    if (!option) throw new Error(`the console offers no deployment on chain ${wanted}`);
    return option.value;
  }, chainId);
  await picker.selectOption(value);
  await expect(page.getByRole('button', { name: /^Connect wallet$/ })).toBeVisible();
}

export async function openConsole(page: Page) {
  await page.goto(ORIGINS.paymasterAdmin);
  // The console reads without a wallet, and the panels only render once that read lands.
  await expect(page.getByRole('tab', { name: /Overview/ })).toBeVisible();
}
