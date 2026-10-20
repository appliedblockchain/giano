/**
 * Setup that only makes sense on a local anvil chain: the infrastructure a public chain already has
 * (CreateX, EntryPoint v0.7), and impersonating the canonical deployer so no key is needed.
 */
import { createRequire } from 'node:module';
import { keccak256, type Address, type Hex, type PublicClient, type TestClient } from 'viem';
import { ENTRY_POINT_V07 } from './config';
import { CREATEX_ADDRESS } from './create3';
import { presignedDeployment } from './createx';

const require = createRequire(import.meta.url);

/**
 * CreateX through its own keyless deployment transaction (pre-EIP-155, so valid on any chain id),
 * which is what puts it at the same address on every public chain.
 */
export async function installCreateX(publicClient: PublicClient, testClient: TestClient, log: (line: string) => void): Promise<void> {
  const existing = await publicClient.getCode({ address: CREATEX_ADDRESS });
  if (existing && existing !== '0x') {
    log(`  = CreateX already at ${CREATEX_ADDRESS}`);
    return;
  }
  const { signer, gasLimit, gasPriceWei, rawTransaction } = presignedDeployment;
  await testClient.setBalance({ address: signer, value: BigInt(gasLimit) * BigInt(gasPriceWei) });
  const hash = await publicClient.request({ method: 'eth_sendRawTransaction', params: [rawTransaction] });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== 'success') throw new Error(`CreateX's presigned deployment reverted (${hash})`);
  const code = await publicClient.getCode({ address: CREATEX_ADDRESS });
  if (!code || code === '0x') throw new Error(`CreateX's presigned deployment did not land at ${CREATEX_ADDRESS}`);
  log(`  + CreateX at ${CREATEX_ADDRESS}`);
}

/**
 * EntryPoint v0.7 at its canonical address. Its runtime code has no constructor-set state, so
 * deploying it anywhere and copying the code is equivalent to the real deployment.
 */
export async function installEntryPoint(publicClient: PublicClient, testClient: TestClient, from: Address, log: (line: string) => void): Promise<void> {
  const existing = await publicClient.getCode({ address: ENTRY_POINT_V07 });
  if (existing && existing !== '0x') {
    log(`  = EntryPoint v0.7 already at ${ENTRY_POINT_V07}`);
    return;
  }
  const artifact = require('@account-abstraction/contracts/artifacts/EntryPoint.json') as { bytecode: Hex };
  // eth_call with no `to` runs the init code and returns the runtime code it would deploy.
  const { data } = await publicClient.call({ account: from, data: artifact.bytecode });
  if (!data) throw new Error('EntryPoint creation code returned no runtime code');
  await testClient.setCode({ address: ENTRY_POINT_V07, bytecode: data });
  log(`  + EntryPoint v0.7 at ${ENTRY_POINT_V07} (${keccak256(data).slice(0, 10)}…)`);
}

/** Lets eth_sendTransaction from `address` succeed without its key, and funds it. */
export async function impersonate(testClient: TestClient, address: Address): Promise<void> {
  await testClient.impersonateAccount({ address });
  await testClient.setBalance({ address, value: 10n ** 21n });
}
