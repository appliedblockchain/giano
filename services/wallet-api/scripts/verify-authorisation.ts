/**
 * Cross-language conformance check for the sponsorship authorisation.
 *
 * Builds a `paymasterData` blob using the *production* encoder and signer, hands it to the
 * deployed `GianoPaymaster`, and asserts the contract accepts it and pins the fields it will
 * later settle against.
 *
 * This exists because the TypeScript ↔ Solidity boundary is the one place in this design where a
 * mistake is both easy and invisible: a byte offset off by one, an EIP-712 field in the wrong
 * order, a `uint48` where the contract reads a `uint128`. None of it shows up in a unit test on
 * either side, and on chain it surfaces as `BadPaymasterData` or a bare `AA34` — after a tenant
 * has funded a balance.
 *
 * Run it after deploying, after upgrading the implementation, and after rotating a signing key:
 *
 *   RPC_URL=http://localhost:8545 \
 *   SPONSORSHIP_PAYMASTER_ADDRESS=0x... \
 *   SPONSORSHIP_SIGNER_KEY_REF=0x... \
 *   PAYMASTER_TENANT_ID=<uuid> \
 *   pnpm --filter @appliedblockchain/giano-wallet-api verify:authorisation
 */
import { gianoPaymasterAbi } from '@appliedblockchain/giano-contracts';
import { createPublicClient, decodeAbiParameters, http, keccak256, concat, numberToHex, type Address, type Hex } from 'viem';
import { encodePaymasterData, tenantIdToBytes16 } from '../src/services/paymaster-contract.js';
import { createLocalSponsorshipSigner } from '../src/services/sponsorship-signer.js';
import { packUints } from '../src/services/sponsorship-service.js';

const ENTRY_POINT = '0x0000000071727De22E5E9d8BAf0edAc6f37da032' as Address;

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

async function main(): Promise<void> {
  const rpcUrl = process.env.RPC_URL ?? 'http://localhost:8545';
  const paymasterAddress = required('SPONSORSHIP_PAYMASTER_ADDRESS') as Address;
  const tenantUuid = required('PAYMASTER_TENANT_ID');
  const signerKey = required('SPONSORSHIP_SIGNER_KEY_REF') as Hex;
  const sender = (process.env.SENDER ?? '0x1111111111111111111111111111111111111234') as Address;

  const client = createPublicClient({ transport: http(rpcUrl) });
  const chainId = await client.getChainId();
  const signer = createLocalSponsorshipSigner(signerKey, 'verify');
  const signerAddress = await signer.address();
  const tenantId = tenantIdToBytes16(tenantUuid);

  console.log(`paymaster ${paymasterAddress} on chain ${chainId}`);
  console.log(`signer    ${signerAddress}`);
  console.log(`tenant    ${tenantUuid} → ${tenantId}`);

  // Fail early on the two preconditions that would otherwise produce a confusing refusal.
  const isSigner = await client.readContract({
    address: paymasterAddress,
    abi: gianoPaymasterAbi,
    functionName: 'isSigner',
    args: [signerAddress],
  });
  if (!isSigner) throw new Error(`${signerAddress} is not in the paymaster's signer set — add it with SIGNER_ADMIN_ROLE`);

  const tenant = (await client.readContract({
    address: paymasterAddress,
    abi: gianoPaymasterAbi,
    functionName: 'getTenant',
    args: [tenantId],
  })) as { registered: boolean; enabled: boolean; balance: bigint };
  if (!tenant.registered) throw new Error(`tenant ${tenantUuid} is not registered on the paymaster`);
  if (!tenant.enabled) throw new Error(`tenant ${tenantUuid} is registered but disabled`);

  const feeWei = (await client.readContract({
    address: paymasterAddress,
    abi: gianoPaymasterAbi,
    functionName: 'feeFor',
    args: [tenantId],
  })) as bigint;

  const callGasLimit = 200_000n;
  const verificationGasLimit = 500_000n;
  const preVerificationGas = 50_000n;
  const maxPriorityFeePerGas = 1_000_000_000n;
  const maxFeePerGas = 2_000_000_000n;
  const paymasterVerificationGasLimit = 150_000n;
  const paymasterPostOpGasLimit = 100_000n;
  const nonce = 0n;
  const callData: Hex = '0xdeadbeef';
  const validAfter = 0;
  const validUntil = Math.floor(Date.now() / 1000) + 300;

  const accountGasLimits = packUints(verificationGasLimit, callGasLimit);
  const gasFees = packUints(maxPriorityFeePerGas, maxFeePerGas);

  const signature = await signer.signAuthorisation({
    chainId,
    paymaster: paymasterAddress,
    sender,
    nonce,
    callData,
    accountGasLimits,
    preVerificationGas,
    gasFees,
    paymasterVerificationGasLimit,
    paymasterPostOpGasLimit,
    tenantId,
    validUntil,
    validAfter,
    feeWei,
  });

  const paymasterData = encodePaymasterData({ tenantId, validUntil, validAfter, feeWei, signer: signerAddress, signature });
  const paymasterAndData = concat([
    paymasterAddress,
    numberToHex(paymasterVerificationGasLimit, { size: 16 }),
    numberToHex(paymasterPostOpGasLimit, { size: 16 }),
    paymasterData,
  ]);

  const maxCost =
    (preVerificationGas + verificationGasLimit + paymasterVerificationGasLimit + paymasterPostOpGasLimit + callGasLimit) * maxFeePerGas;

  if (tenant.balance < maxCost + feeWei) {
    throw new Error(`tenant balance ${tenant.balance} cannot cover this probe's ${maxCost + feeWei} wei — fund it first`);
  }

  // Simulated as the EntryPoint, the only caller the contract accepts.
  const { result } = await client.simulateContract({
    address: paymasterAddress,
    abi: gianoPaymasterAbi,
    functionName: 'validatePaymasterUserOp',
    args: [
      {
        sender,
        nonce,
        initCode: '0x',
        callData,
        accountGasLimits,
        preVerificationGas,
        gasFees,
        paymasterAndData,
        signature: '0x',
      },
      keccak256('0xcafe'),
      maxCost,
    ],
    account: ENTRY_POINT,
  });

  const [context, validationData] = result as unknown as [Hex, bigint];

  if (validationData === 1n) {
    throw new Error('SIG_VALIDATION_FAILED: the contract did not accept the authorisation this service produced');
  }
  const expected = BigInt(validUntil) << 160n;
  if (validationData !== expected) {
    throw new Error(`validationData ${validationData} does not encode the validity window (expected ${expected})`);
  }

  const [ctxTenant, ctxFee, ctxExecutionGas, ctxSender] = decodeAbiParameters(
    [{ type: 'bytes16' }, { type: 'uint128' }, { type: 'uint256' }, { type: 'address' }, { type: 'bytes32' }],
    context,
  );

  // What is pinned here is what `postOp` will settle against, so a mismatch would bill the wrong
  // tenant or charge the wrong fee.
  if (ctxTenant !== tenantId) throw new Error(`context pins tenant ${ctxTenant}, expected ${tenantId}`);
  if (ctxFee !== feeWei) throw new Error(`context pins fee ${ctxFee}, expected ${feeWei}`);
  if (ctxExecutionGas !== callGasLimit + paymasterPostOpGasLimit) {
    throw new Error(`context pins execution gas ${ctxExecutionGas}, expected ${callGasLimit + paymasterPostOpGasLimit}`);
  }
  if ((ctxSender as string).toLowerCase() !== sender.toLowerCase()) {
    throw new Error(`context pins sender ${ctxSender}, expected ${sender}`);
  }

  console.log(`\nPASS: the contract accepted the authorisation and pinned tenant ${ctxTenant}, fee ${ctxFee} wei.`);
}

main().catch((error: unknown) => {
  console.error(`\nFAIL: ${(error as Error).message}`);
  process.exit(1);
});
