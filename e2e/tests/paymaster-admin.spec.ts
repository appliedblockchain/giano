import { expect, test } from '@playwright/test';
import { createPublicClient, formatEther, http, parseEther } from 'viem';

import { CHAINS } from '../origins.mjs';
import { chooseDeployment, installWallet, openConsole, OPERATOR, walletCalls, walletChain } from './console-wallet';

/**
 * The paymaster console's wallet path, against the real console and the real devnets.
 *
 * Everything the console writes is signed by an injected browser wallet, which means the one part
 * no other suite reaches is also the part hardest to cover: a real extension cannot be driven, and
 * the console's own unit surface stops at the EIP-1193 boundary. So a wallet is scripted into the
 * page — the same shape MetaMask presents, including the rules it enforces on
 * `wallet_addEthereumChain` — and the console is then used exactly as an operator would.
 *
 * Its accounts are anvil's own, unlocked on the devnet, so `eth_sendTransaction` is signed by the
 * node and a write in the console lands on chain for real. JSON-RPC is forwarded through the
 * console's own `/rpc/<chainId>` proxy because that is same-origin: anvil sends no CORS headers,
 * which is the whole reason the proxy exists.
 */

test("connect moves the wallet to the console's chain on its own, with nothing to click", async ({ page }) => {
  await installWallet(page, { known: [CHAINS.a.chainId] });
  await openConsole(page);
  await chooseDeployment(page, CHAINS.a.chainId);

  await page.getByRole('button', { name: /^Connect wallet$/ }).click();

  await expect(page.getByRole('button', { name: /^Connected/ })).toBeVisible();
  expect(await walletChain(page)).toBe(`0x${CHAINS.a.chainId.toString(16)}`);
  expect(await walletCalls(page)).toContain('wallet_switchEthereumChain');
  // The operator was never asked to do it — the old affordance is gone, not merely bypassed.
  await expect(page.getByRole('button', { name: /^Switch to/ })).toHaveCount(0);
  await expect(page.getByText('Wrong network')).toHaveCount(0);
});

test('the wallet card names the account, the network and what that account may do', async ({ page }) => {
  await installWallet(page, { known: [CHAINS.a.chainId] });
  await openConsole(page);
  await chooseDeployment(page, CHAINS.a.chainId);
  await page.getByRole('button', { name: /^Connect wallet$/ }).click();

  await page.getByRole('button', { name: /^Connected/ }).click();

  const card = page.getByRole('dialog');
  await expect(card.getByText(OPERATOR)).toBeVisible();
  await expect(card.getByText(`chain ${CHAINS.a.chainId}`, { exact: false })).toBeVisible();
  await expect(card.getByText(/on this paymaster/)).toBeVisible();
  // The header's other address is the paymaster's, and is labelled as such rather than left bare.
  await expect(page.getByText('Paymaster', { exact: true })).toBeVisible();
});

test('a chain the wallet has never seen is added with the address published for wallets', async ({ page }) => {
  await installWallet(page, { known: [] });
  await openConsole(page);
  await chooseDeployment(page, CHAINS.b.chainId);

  await page.getByRole('button', { name: /^Connect wallet$/ }).click();
  await expect(page.getByRole('button', { name: /^Connected/ })).toBeVisible();

  const added = await page.evaluate(() => window.__wallet.calls.find((call) => call.method === 'wallet_addEthereumChain'));
  const params = added?.params[0] as { chainId: string; rpcUrls: string[] };
  expect(params.chainId).toBe(`0x${CHAINS.b.chainId.toString(16)}`);
  // walletRpcUrl, not the console's own /rpc/<chainId> proxy path, which no wallet could dial.
  expect(params.rpcUrls[0]).toMatch(/^http:\/\/localhost:8546\/?$/);
  expect(await walletChain(page)).toBe(`0x${CHAINS.b.chainId.toString(16)}`);
});

test('a wallet that will not add a network is answered with the details to add it by hand', async ({ page }) => {
  await installWallet(page, { known: [], refuseAdd: true });
  await openConsole(page);
  await chooseDeployment(page, CHAINS.b.chainId);

  await page.getByRole('button', { name: /^Connect wallet$/ }).click();

  await expect(page.getByText(/Add .* in your wallet/)).toBeVisible();
  // Read out of a serialised JSON-RPC object rather than printed as [object Object].
  await expect(page.getByText('this wallet does not add networks')).toBeVisible();
  await expect(page.getByText('Chain ID', { exact: true })).toBeVisible();
  await expect(page.getByText(String(CHAINS.b.chainId), { exact: true })).toBeVisible();
  await expect(page.getByText('RPC URL', { exact: true })).toBeVisible();
});

test('a write is signed by the connected wallet and lands on the chain', async ({ page }) => {
  await installWallet(page, { known: [CHAINS.a.chainId] });
  await openConsole(page);
  await chooseDeployment(page, CHAINS.a.chainId);
  await page.getByRole('button', { name: /^Connect wallet$/ }).click();
  await expect(page.getByRole('button', { name: /^Connected/ })).toBeVisible();

  const chain = createPublicClient({ transport: http(CHAINS.a.rpc) });
  const paymaster = (await page.evaluate(async () => (await (await fetch('/config.json')).json()).deployments[0].sponsorshipPaymaster)) as `0x${string}`;
  const feeOnChain = () =>
    chain.readContract({
      address: paymaster,
      abi: [{ type: 'function', name: 'defaultFeeWei', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] }],
      functionName: 'defaultFeeWei',
    });

  // One devnet serves the whole suite, and what this paymaster charges is what the sponsorship
  // tests do their arithmetic against. The fee goes back before this test ends.
  const before = await feeOnChain();

  // Deliberately not waiting on the toast: it outlives the write that raised it, so a second
  // write would match the first one's confirmation and pass without having done anything.
  const setFee = async (value: string) => {
    await page.getByRole('tab', { name: /Settings/ }).click();
    await page.getByLabel('New default fee (ETH)').fill(value);
    await page.getByRole('button', { name: /^Set$/ }).first().click();
  };

  // A value no earlier run would leave behind, so a stale read cannot pass for a fresh write.
  const fee = `0.000${Math.floor(Math.random() * 900) + 100}`;

  try {
    await setFee(fee);

    await expect(page.getByText('Set default fee confirmed')).toBeVisible({ timeout: 60_000 });
    expect(await walletCalls(page)).toContain('eth_sendTransaction');
    // The console says it landed; the chain is what settles it.
    await expect.poll(feeOnChain, { timeout: 30_000 }).toBe(parseEther(fee));
  } finally {
    // Even on a failed assertion. This suite runs one worker in file order, so a fee left behind
    // here is a fee the sponsorship tests would do their arithmetic against.
    if ((await feeOnChain()) !== before) {
      await setFee(formatEther(before));
      await expect.poll(feeOnChain, { timeout: 60_000 }).toBe(before);
    }
  }
});
