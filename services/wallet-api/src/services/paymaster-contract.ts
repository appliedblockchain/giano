import { gianoPaymasterAbi } from '@appliedblockchain/giano-contracts';
import type { Address, Hex, PublicClient } from 'viem';
import { concat, encodeAbiParameters, keccak256, numberToHex, pad } from 'viem';

/**
 * Reads the paymaster's on-chain configuration, and builds the `paymasterData` the contract
 * parses.
 *
 * The fee is read from the *contract*, never from service configuration, so that what an
 * authorisation pins is what the chain will actually charge — and so a tenant can verify a charge
 * from readable on-chain data rather than from Giano's books.
 */

export const PAYMASTER_DATA_VERSION = 0x01;

export type PaymasterOnChainParams = {
  postOpGasAllowance: bigint;
  penaltyBps: bigint;
  defaultFeeWei: bigint;
};

export type PaymasterTenantState = {
  registered: boolean;
  enabled: boolean;
  withdrawAddress: Address;
  balanceWei: bigint;
  deficitWei: bigint;
  feeWei: bigint;
};

export type PaymasterReader = {
  address: Address;
  params: () => Promise<PaymasterOnChainParams>;
  feeFor: (tenantId: Hex) => Promise<bigint>;
  tenant: (tenantId: Hex) => Promise<PaymasterTenantState>;
  treasury: () => Promise<bigint>;
  deposit: () => Promise<bigint>;
  isSigner: (address: Address) => Promise<boolean>;
  paused: () => Promise<boolean>;
  blockNumber: () => Promise<bigint>;
};

export type PaymasterReaderOptions = {
  client: PublicClient;
  address: Address;
  /**
   * How long the parameters and per-tenant fee may be served from cache. Short by design: these
   * change through a timelocked role, so a brief staleness is fine, but pinning a fee the chain
   * no longer charges would make every affected operation fail validation.
   */
  cacheTtlMs?: number;
};

type Cached<T> = { value: T; at: number };

export function createPaymasterReader(options: PaymasterReaderOptions): PaymasterReader {
  const { client, address } = options;
  const ttl = options.cacheTtlMs ?? 15_000;
  const contract = { address, abi: gianoPaymasterAbi } as const;

  let paramsCache: Cached<PaymasterOnChainParams> | undefined;
  const feeCache = new Map<string, Cached<bigint>>();

  const fresh = <T>(cached: Cached<T> | undefined): T | undefined =>
    cached && Date.now() - cached.at < ttl ? cached.value : undefined;

  return {
    address,

    async params() {
      const cached = fresh(paramsCache);
      if (cached) return cached;

      const [postOpGasAllowance, penaltyBps, defaultFeeWei] = await Promise.all([
        client.readContract({ ...contract, functionName: 'postOpGasAllowance' }),
        client.readContract({ ...contract, functionName: 'penaltyBps' }),
        client.readContract({ ...contract, functionName: 'defaultFeeWei' }),
      ]);

      const value: PaymasterOnChainParams = {
        postOpGasAllowance: BigInt(postOpGasAllowance),
        penaltyBps: BigInt(penaltyBps),
        defaultFeeWei: BigInt(defaultFeeWei),
      };
      paramsCache = { value, at: Date.now() };
      return value;
    },

    async feeFor(tenantId) {
      const cached = fresh(feeCache.get(tenantId));
      if (cached !== undefined) return cached;
      const fee = (await client.readContract({ ...contract, functionName: 'feeFor', args: [tenantId] })) as bigint;
      feeCache.set(tenantId, { value: fee, at: Date.now() });
      return fee;
    },

    async tenant(tenantId) {
      const [state, fee] = await Promise.all([
        client.readContract({ ...contract, functionName: 'getTenant', args: [tenantId] }) as Promise<{
          registered: boolean;
          enabled: boolean;
          hasFeeOverride: boolean;
          withdrawAddress: Address;
          balance: bigint;
          deficit: bigint;
          feeWeiOverride: bigint;
        }>,
        client.readContract({ ...contract, functionName: 'feeFor', args: [tenantId] }) as Promise<bigint>,
      ]);
      return {
        registered: state.registered,
        enabled: state.enabled,
        withdrawAddress: state.withdrawAddress,
        balanceWei: BigInt(state.balance),
        deficitWei: BigInt(state.deficit),
        feeWei: BigInt(fee),
      };
    },

    treasury: async () => BigInt((await client.readContract({ ...contract, functionName: 'treasury' })) as bigint),
    deposit: async () => BigInt((await client.readContract({ ...contract, functionName: 'getDeposit' })) as bigint),
    isSigner: async (signer) => (await client.readContract({ ...contract, functionName: 'isSigner', args: [signer] })) as boolean,
    paused: async () => (await client.readContract({ ...contract, functionName: 'paused' })) as boolean,
    blockNumber: () => client.getBlockNumber(),
  };
}

/**
 * The 16-byte tenant id the contract keys on.
 *
 * Giano's `tenants.id` is a UUID, which is already immutable, already unique and never reused —
 * so it is used directly rather than introducing a second identifier that would then have to be
 * kept in step with it.
 */
export function tenantIdToBytes16(tenantUuid: string): Hex {
  const hex = tenantUuid.replace(/-/g, '').toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(hex)) throw new Error(`not a UUID: ${tenantUuid}`);
  return `0x${hex}`;
}

export type PaymasterDataFields = {
  tenantId: Hex;
  validUntil: number;
  validAfter: number;
  feeWei: bigint;
  signer: Address;
  signature: Hex;
};

/**
 * Lays out `paymasterData` exactly as `GianoPaymaster` parses it:
 *
 *   version(1) ‖ tenantId(16) ‖ validUntil(6) ‖ validAfter(6) ‖ feeWei(16) ‖ signer(20) ‖ signature
 *
 * The signer travels with the signature so verification is one membership test plus one check
 * rather than a loop over the authorised set.
 */
export function encodePaymasterData(fields: PaymasterDataFields): Hex {
  return concat([
    numberToHex(PAYMASTER_DATA_VERSION, { size: 1 }),
    pad(fields.tenantId, { size: 16, dir: 'left' }),
    numberToHex(fields.validUntil, { size: 6 }),
    numberToHex(fields.validAfter, { size: 6 }),
    numberToHex(fields.feeWei, { size: 16 }),
    fields.signer,
    fields.signature,
  ]);
}

/**
 * The operation's hash, computed the way the EntryPoint computes it.
 *
 * Worth doing here rather than waiting for the chain to tell us: the hash is fully determined once
 * the authorisation is signed — it covers `paymasterAndData` but *not* the account signature — so
 * the service can record it against the reservation at issue time. Without it the watcher has
 * nothing to match a `Sponsored` event to, because that event carries the hash and not the nonce,
 * and every reservation would sit until its TTL expired while the tenant's balance looked spent.
 */
export function computeUserOpHash(args: {
  sender: Address;
  nonce: bigint;
  initCode: Hex;
  callData: Hex;
  accountGasLimits: Hex;
  preVerificationGas: bigint;
  gasFees: Hex;
  paymasterAndData: Hex;
  entryPoint: Address;
  chainId: number;
}): Hex {
  const packed = keccak256(
    encodeAbiParameters(
      [
        { type: 'address' },
        { type: 'uint256' },
        { type: 'bytes32' },
        { type: 'bytes32' },
        { type: 'bytes32' },
        { type: 'uint256' },
        { type: 'bytes32' },
        { type: 'bytes32' },
      ],
      [
        args.sender,
        args.nonce,
        keccak256(args.initCode),
        keccak256(args.callData),
        args.accountGasLimits,
        args.preVerificationGas,
        args.gasFees,
        keccak256(args.paymasterAndData),
      ],
    ),
  );
  return keccak256(
    encodeAbiParameters([{ type: 'bytes32' }, { type: 'address' }, { type: 'uint256' }], [packed, args.entryPoint, BigInt(args.chainId)]),
  );
}

/** `paymasterAndData` as the EntryPoint lays it out: the prefix, then the authorisation header. */
export function encodePaymasterAndData(args: {
  paymaster: Address;
  paymasterVerificationGasLimit: bigint;
  paymasterPostOpGasLimit: bigint;
  paymasterData: Hex;
}): Hex {
  return concat([
    args.paymaster,
    numberToHex(args.paymasterVerificationGasLimit, { size: 16 }),
    numberToHex(args.paymasterPostOpGasLimit, { size: 16 }),
    args.paymasterData,
  ]);
}

/**
 * A stub with a correctly-sized dummy signature.
 *
 * The size is what matters: gas estimation runs against this, and a stub shorter than the real
 * thing would produce a `preVerificationGas` too low for the operation that eventually lands.
 */
export function encodeStubPaymasterData(fields: Omit<PaymasterDataFields, 'signature'>): Hex {
  return encodePaymasterData({ ...fields, signature: `0x${'00'.repeat(65)}` });
}
