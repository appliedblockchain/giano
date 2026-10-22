import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { createRequire } from 'node:module';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import {
  createPublicClient,
  createTestClient,
  createWalletClient,
  encodeFunctionData,
  getAddress,
  http,
  parseEther,
  toHex,
  type Address,
  type Hex,
  type PublicClient,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';
import { pino } from 'pino';
import { DEFAULT_ENTRYPOINT } from '../src/config.js';
import { createEstimator } from '../src/estimator.js';
import { createLookup } from '../src/lookup.js';
import { createMetrics } from '../src/metrics.js';
import { createRpcServer } from '../src/rpc.js';
import { createSubmitter, type Submitter } from '../src/submitter.js';

const require = createRequire(import.meta.url);
const artifact = (name: string) => require(`@account-abstraction/contracts/artifacts/${name}.json`) as { abi: any; bytecode: Hex };

/** Anvil's deterministic accounts: 0 deploys, 1 executes, 2 signs sponsorships, 3 owns the test accounts. */
export const KEYS = {
  deployer: '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
  executor: '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
  sponsor: '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a',
  owner: '0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6',
} as const satisfies Record<string, Hex>;

export const anvilAvailable = spawnSync('anvil', ['--version']).status === 0;

export type Devnet = {
  rpcUrl: string;
  client: PublicClient;
  test: ReturnType<typeof createTestClient>;
  wallet: ReturnType<typeof createWalletClient>;
  entryPoint: Address;
  factory: Address;
  paymaster: Address;
  stop: () => void;
};

export async function startDevnet(): Promise<Devnet> {
  const port = 20_000 + Math.floor(Math.random() * 20_000);
  const anvil: ChildProcess = spawn('anvil', ['--port', String(port), '--silent', '--chain-id', '31337'], { stdio: 'ignore' });
  const rpcUrl = `http://127.0.0.1:${port}`;
  const client = createPublicClient({ chain: foundry, transport: http(rpcUrl) }) as PublicClient;
  for (let i = 0; ; i++) {
    try {
      await client.getChainId();
      break;
    } catch (error) {
      if (i > 100) throw error;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  const deployer = privateKeyToAccount(KEYS.deployer);
  const wallet = createWalletClient({ account: deployer, chain: foundry, transport: http(rpcUrl) });
  const test = createTestClient({ mode: 'anvil', chain: foundry, transport: http(rpcUrl) });

  const deploy = async (name: string, args: unknown[] = []) => {
    const { abi, bytecode } = artifact(name);
    const hash = await wallet.deployContract({ abi, bytecode, args, account: deployer, chain: foundry });
    const receipt = await client.waitForTransactionReceipt({ hash });
    return getAddress(receipt.contractAddress!);
  };

  // As the e2e devnet does it: deploy anywhere, copy the runtime code to the canonical address.
  // That leaves no SenderCreator at the canonical EntryPoint's first CREATE address, which is the
  // case the estimator has to cope with.
  const deployed = await deploy('EntryPoint');
  await test.setCode({ address: DEFAULT_ENTRYPOINT, bytecode: (await client.getCode({ address: deployed }))! });
  // setCode copies no storage, and the reentrancy guard's slot would then start at zero: the first
  // handleOps would pay ~20k gas to create it, which no real EntryPoint does. Copy what the
  // constructor wrote.
  for (let slot = 0n; slot < 8n; slot++) {
    const value = await client.getStorageAt({ address: deployed, slot: toHex(slot, { size: 32 }) });
    if (value && BigInt(value) !== 0n) await test.setStorageAt({ address: DEFAULT_ENTRYPOINT, index: toHex(slot, { size: 32 }), value });
  }
  const entryPoint = DEFAULT_ENTRYPOINT;

  const factory = await deploy('SimpleAccountFactory', [entryPoint]);
  const paymaster = await deploy('VerifyingPaymaster', [entryPoint, privateKeyToAccount(KEYS.sponsor).address]);
  const { abi: paymasterAbi } = artifact('VerifyingPaymaster');
  await client.waitForTransactionReceipt({
    hash: await wallet.writeContract({ address: paymaster, abi: paymasterAbi, functionName: 'deposit', args: [], value: parseEther('10'), account: deployer, chain: foundry }),
  });

  return { rpcUrl, client, test, wallet, entryPoint, factory, paymaster, stop: () => anvil.kill() };
}

export type Bundler = { url: string; submitter: Submitter; stop: () => Promise<void> };

export async function startBundler(
  devnet: Devnet,
  options: { resubmitTimeoutMs?: number; maxReplacements?: number } = {},
): Promise<Bundler> {
  const executor = privateKeyToAccount(KEYS.executor);
  const log = pino({ level: process.env.BUNDLER_TEST_LOG ?? 'silent' });
  const metrics = createMetrics();
  const chainId = 31337;
  const submitter = createSubmitter({
    client: devnet.client,
    chainId,
    entryPoint: devnet.entryPoint,
    executors: [executor],
    resubmitTimeoutMs: options.resubmitTimeoutMs ?? 60_000,
    maxReplacements: options.maxReplacements ?? 3,
    pollIntervalMs: 50,
    log,
    metrics,
  });
  const estimator = createEstimator({ client: devnet.client, entryPoint: devnet.entryPoint, chainId, chainType: 'default', executor: executor.address });
  const lookup = createLookup({ client: devnet.client, chainId, entryPoint: devnet.entryPoint, maxBlockRange: 2000n, submitter });
  const server: Server = createRpcServer({ chainId, entryPoint: devnet.entryPoint, estimator, submitter, lookup, metrics, log }, () => true);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    submitter,
    stop: () =>
      new Promise((resolve) => {
        submitter.stop();
        server.close(() => resolve());
      }),
  };
}

let rpcId = 0;
export async function rpc<T = any>(url: string, method: string, params: unknown[] = []): Promise<{ result?: T; error?: { code: number; message: string } }> {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params }),
  });
  return response.json() as never;
}

export const simpleAccountAbi = artifact('SimpleAccount').abi;
export const simpleAccountFactoryAbi = artifact('SimpleAccountFactory').abi;
export const verifyingPaymasterAbi = artifact('VerifyingPaymaster').abi;

export const executeCall = (to: Address, value: bigint, data: Hex = '0x') =>
  encodeFunctionData({ abi: simpleAccountAbi, functionName: 'execute', args: [to, value, data] });
