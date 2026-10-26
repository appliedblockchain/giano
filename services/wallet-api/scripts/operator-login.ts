/**
 * Signs in to a wallet-api's operator tier from a private key and prints the session token.
 *
 * Runs the same EIP-4361 challenge and verify the console does (specs/OPERATOR-ADMIN-SPECS.md
 * §4.2), for acceptance on dev with a throwaway EOA listed in that deployment's
 * OPERATOR_ADDRESSES and nowhere else. A real operator uses the console and their own wallet.
 *
 *   OPERATOR_PRIVATE_KEY=0x... \
 *   pnpm -s --filter @appliedblockchain/giano-wallet-api operator:login --api https://api.dev.giano.appliedblockchain.dev
 *
 * The token goes to stdout alone, so it can be captured: `set -l token (… operator:login …)`.
 * Everything else goes to stderr.
 */
import type { Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function argument(flag: string): string | undefined {
  const index = process.argv.indexOf(flag);
  return index === -1 ? undefined : process.argv[index + 1];
}

async function post<T>(url: string, body: unknown): Promise<T> {
  // no Origin header: operator routes refuse any request that carries one
  const response = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  if (!response.ok) throw new Error(`${url} answered ${response.status}: ${await response.text()}`);
  return (await response.json()) as T;
}

async function main(): Promise<void> {
  const api = (argument('--api') ?? process.env.WALLET_API_URL ?? 'http://localhost:3000').replace(/\/$/, '');
  const chainId = Number(argument('--chain-id') ?? '1');
  const account = privateKeyToAccount(required('OPERATOR_PRIVATE_KEY') as Hex);

  const { message } = await post<{ message: string }>(`${api}/v1/operator/auth/challenge`, { address: account.address, chainId });
  const signature = await account.signMessage({ message });
  const session = await post<{ token: string; expiresAt: string; operator: { id: string } }>(`${api}/v1/operator/auth/verify`, { message, signature });

  console.error(`signed in as ${session.operator.id} (${account.address}) until ${session.expiresAt}`);
  console.log(session.token);
}

main().catch((error: Error) => {
  console.error(error.message);
  process.exit(1);
});
