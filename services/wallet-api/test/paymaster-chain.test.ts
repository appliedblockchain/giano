import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { PostgreSqlContainer, type StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import { gianoSmartWalletAbi, gianoSmartWalletFactoryAbi } from '@appliedblockchain/giano-contracts';
import { and, eq } from 'drizzle-orm';
import type { Address, Hex, PublicClient } from 'viem';
import { createPublicClient, createWalletClient, encodeAbiParameters, encodeFunctionData, http, parseEther } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createDb, type Db } from '../src/db/index.js';
import { credentials, paymasterTenants, sessions, sponsorshipSettlements, tenants, users } from '../src/db/schema.js';
import { runMigrations } from '../src/migrate.js';
import { createPaymasterReader, type PaymasterReader } from '../src/services/paymaster-contract.js';
import { createPaymasterWatcher, type PaymasterWatcher } from '../src/services/paymaster-watcher.js';
import { createLedgerService, type LedgerService } from '../src/services/sponsorship-ledger.js';
import { createSponsorshipService, packUints, type SponsorshipService } from '../src/services/sponsorship-service.js';
import { createLocalSponsorshipSigner } from '../src/services/sponsorship-signer.js';
import { tenantSponsorship } from '../src/db/schema.js';

/**
 * The sponsorship path against a real chain.
 *
 * Everything here is real except the bundler: a real anvil loaded from the committed devnet state,
 * the real EntryPoint, the real paymaster with real per-tenant balances, an authorisation signed by
 * the real signer through the real service, submitted through `EntryPoint.handleOps` directly, and
 * settled by the real watcher.
 *
 * It exists because none of the other suites can catch a mismatch *between* the pieces. The
 * contract tests drive the contract with hand-built bytes; the service tests drive the service
 * against a fake chain. Only here does a `paymasterData` blob the service produced have to be
 * accepted by the contract, and only here does the watcher have to make the ledger agree with what
 * the chain actually charged.
 *
 * The account is owned by an ECDSA key rather than a passkey, because signing WebAuthn in Node
 * would test the fixture rather than the sponsorship.
 */

const STATE_PATH = path.resolve(import.meta.dirname, '..', '..', '..', 'e2e', 'devnet', 'state.json');
const ANVIL_PORT = 8547;
/**
 * The same pinned foundry image the deployment and the state generator use.
 *
 * Deliberately not a local `anvil`: `--load-state` parsing is version-specific, so a developer's
 * anvil may simply refuse the committed state — and the failure mode there is this whole suite
 * quietly not running, which is worse than it failing.
 */
const ANVIL_IMAGE = 'ghcr.io/foundry-rs/foundry@sha256:8347b728d5d393dac1c018691b36f506d23b9dcd78341d40ea0fcb11c3a19cdd';
const ANVIL_CONTAINER = 'giano-paymaster-chain-test';
const RPC_URL = `http://127.0.0.1:${ANVIL_PORT}`;
const CHAIN_ID = 31337;
const ENTRY_POINT = '0x0000000071727De22E5E9d8BAf0edAc6f37da032' as Address;

const hasState = fs.existsSync(STATE_PATH);
if (!hasState) {
  // Loud, not silent: a suite that skips itself because a fixture is missing looks identical to a
  // suite that passed.
  // eslint-disable-next-line no-console
  console.warn(
    `SKIPPING the real-chain paymaster suite: ${STATE_PATH} is missing.\n` +
      'Generate it with `pnpm --filter @appliedblockchain/giano-e2e devnet:generate`.',
  );
}
const devnet = hasState
  ? (JSON.parse(fs.readFileSync(STATE_PATH.replace('state.json', 'addresses.json'), 'utf8')) as {
      factory: Address;
      sponsorshipPaymaster: Address;
      sponsorshipSignerKey: Hex;
      testErc20: Address;
      tenants: Array<{ slug: string; id: string }>;
    })
  : undefined;

/** Anvil account 0 — funds the account and submits the bundle in place of a bundler. */
const BUNDLER_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' as Hex;
/** The wallet owner. Anvil account 5, unused by anything else in the baked state. */
const OWNER_KEY = '0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba' as Hex;

const ENTRY_POINT_ABI = [
  {
    type: 'function',
    name: 'handleOps',
    stateMutability: 'nonpayable',
    inputs: [
      {
        name: 'ops',
        type: 'tuple[]',
        components: [
          { name: 'sender', type: 'address' },
          { name: 'nonce', type: 'uint256' },
          { name: 'initCode', type: 'bytes' },
          { name: 'callData', type: 'bytes' },
          { name: 'accountGasLimits', type: 'bytes32' },
          { name: 'preVerificationGas', type: 'uint256' },
          { name: 'gasFees', type: 'bytes32' },
          { name: 'paymasterAndData', type: 'bytes' },
          { name: 'signature', type: 'bytes' },
        ],
      },
      { name: 'beneficiary', type: 'address' },
    ],
    outputs: [],
  },
  {
    type: 'function',
    name: 'getNonce',
    stateMutability: 'view',
    inputs: [
      { name: 'sender', type: 'address' },
      { name: 'key', type: 'uint192' },
    ],
    outputs: [{ name: 'nonce', type: 'uint256' }],
  },
  {
    type: 'function',
    name: 'getUserOpHash',
    stateMutability: 'view',
    inputs: [
      {
        name: 'userOp',
        type: 'tuple',
        components: [
          { name: 'sender', type: 'address' },
          { name: 'nonce', type: 'uint256' },
          { name: 'initCode', type: 'bytes' },
          { name: 'callData', type: 'bytes' },
          { name: 'accountGasLimits', type: 'bytes32' },
          { name: 'preVerificationGas', type: 'uint256' },
          { name: 'gasFees', type: 'bytes32' },
          { name: 'paymasterAndData', type: 'bytes' },
          { name: 'signature', type: 'bytes' },
        ],
      },
    ],
    outputs: [{ name: '', type: 'bytes32' }],
  },
  { type: 'function', name: 'balanceOf', stateMutability: 'view', inputs: [{ name: 'account', type: 'address' }], outputs: [{ name: '', type: 'uint256' }] },
] as const;

describe.skipIf(!hasState)('sponsorship against a real chain', () => {
  let container: StartedPostgreSqlContainer;
  let db: Db;
  let pool: { end: () => Promise<void> };
  let client: PublicClient;
  let paymaster: PaymasterReader;
  let ledger: LedgerService;
  let service: SponsorshipService;
  let watcher: PaymasterWatcher;
  let poolRaw: import('pg').Pool;

  let tenantId: string;
  let walletAddress: Address;
  /** Real rows: the decision record has real foreign keys, and a fabricated id would not insert. */
  let session: { sessionId: string; tenantId: string; userId: string; externalUserId: string; credentialId: string; walletAddress: string };

  const owner = privateKeyToAccount(OWNER_KEY);
  const bundler = privateKeyToAccount(BUNDLER_KEY);

  beforeAll(async () => {
    // A leftover container from an interrupted run would serve the wrong chain.
    spawnSync('docker', ['rm', '-f', ANVIL_CONTAINER], { stdio: 'ignore' });
    const started = spawnSync(
      'docker',
      [
        'run', '-d', '--name', ANVIL_CONTAINER,
        '-p', `${ANVIL_PORT}:8545`,
        '-v', `${STATE_PATH}:/devnet/state.json:ro`,
        '--entrypoint', 'anvil', ANVIL_IMAGE,
        '--host', '0.0.0.0', '--chain-id', String(CHAIN_ID), '--load-state', '/devnet/state.json', '--silent',
      ],
      { encoding: 'utf8' },
    );
    if (started.status !== 0) {
      throw new Error(`could not start the pinned anvil (is Docker running?):\n${started.stderr ?? ''}`);
    }

    client = createPublicClient({ chain: { ...foundry, id: CHAIN_ID }, transport: http(RPC_URL) }) as PublicClient;
    let up = false;
    for (let i = 0; i < 120 && !up; i++) {
      try {
        await client.getBlockNumber();
        up = true;
      } catch {
        await new Promise((resolve) => setTimeout(resolve, 250));
      }
    }
    if (!up) {
      const logs = spawnSync('docker', ['logs', ANVIL_CONTAINER], { encoding: 'utf8' });
      throw new Error(`the pinned anvil never came up:\n${logs.stdout ?? ''}${logs.stderr ?? ''}`);
    }

    container = await new PostgreSqlContainer('postgres:17-alpine').start();
    await runMigrations(container.getConnectionUri());
    const created = createDb(container.getConnectionUri());
    db = created.db;
    pool = created.pool;
    poolRaw = created.pool as unknown as import('pg').Pool;

    // The tenant row must carry the *same* id the paymaster was registered against, or the service
    // would bill a tenant the contract has never heard of.
    tenantId = devnet!.tenants[0].id;
    await db.insert(tenants).values({
      id: tenantId,
      slug: devnet!.tenants[0].slug,
      walletOrigin: 'http://wallet.localhost:8081',
      rpId: 'wallet.localhost',
      rpName: 'Chain test',
      expectedOrigins: ['http://wallet.localhost:8081'],
    });

    paymaster = createPaymasterReader({ client, address: devnet!.sponsorshipPaymaster, cacheTtlMs: 0 });
    ledger = createLedgerService(db);

    service = createSponsorshipService({
      db,
      chainId: CHAIN_ID,
      paymaster,
      ledger,
      signer: createLocalSponsorshipSigner(devnet!.sponsorshipSignerKey, 'chain-test'),
      entryPoint: ENTRY_POINT,
      validitySeconds: 600,
      reservationTtlSeconds: 900,
      // Generous: this suite's subject is the on-chain accounting, not the wallet-management cap.
      walletManagementCapWei: 10n ** 18n,
      isEmergencyStopped: () => false,
    });

    watcher = createPaymasterWatcher({
      db,
      pool: poolRaw,
      client,
      paymaster,
      ledger,
      chainId: CHAIN_ID,
      pollMs: 1000,
      confirmations: 0,
      reconcileIntervalMs: 1000,
      tenantSlug: async () => devnet!.tenants[0].slug,
    });

    // Sponsorship rules, and the balance the reservation ledger reads.
    await db.insert(tenantSponsorship).values({
      tenantId,
      chainId: CHAIN_ID,
      config: {
        enabled: true,
        maxCostPerTxWei: parseEther('1').toString(),
        allowlist: [{ contract: devnet!.testErc20.toLowerCase(), functions: 'all' }],
      },
    });
    // The first reconciliation is what makes the ledger know the on-chain balance — proving the
    // cache converges from the contract rather than depending on an event lookback window.
    await watcher.reconcileOnce();

    walletAddress = await deployWallet();

    const [user] = await db.insert(users).values({ tenantId, externalId: 'chain-test' }).returning({ id: users.id });
    const [credential] = await db
      .insert(credentials)
      .values({
        tenantId,
        userId: user.id,
        credentialId: 'chain-test-credential',
        rpId: 'wallet.localhost',
        cosePublicKey: Buffer.from('00', 'hex'),
        publicKeyX: '0x0',
        publicKeyY: '0x0',
        walletAddress,
      })
      .returning({ id: credentials.id });
    const [sessionRow] = await db
      .insert(sessions)
      .values({
        userId: user.id,
        credentialId: credential.id,
        tokenHash: 'chain-test-token-hash',
        expiresAt: new Date(Date.now() + 3_600_000),
      })
      .returning({ id: sessions.id });

    session = {
      sessionId: sessionRow.id,
      tenantId,
      userId: user.id,
      externalUserId: 'chain-test',
      credentialId: credential.id,
      walletAddress,
    };
  }, 240_000);

  afterAll(async () => {
    await watcher?.stop();
    await pool?.end();
    await container?.stop();
    spawnSync('docker', ['rm', '-f', ANVIL_CONTAINER], { stdio: 'ignore' });
  });

  /** Deploys a Giano wallet owned by an ECDSA key, so it can sign without WebAuthn. */
  async function deployWallet(): Promise<Address> {
    const wallet = createWalletClient({ account: bundler, chain: { ...foundry, id: CHAIN_ID }, transport: http(RPC_URL) });
    const owners = [encodeAbiParameters([{ type: 'address' }], [owner.address])];

    const predicted = (await client.readContract({
      address: devnet!.factory,
      abi: gianoSmartWalletFactoryAbi,
      functionName: 'getAddress',
      args: [owners, 0n],
    })) as Address;

    const hash = await wallet.writeContract({
      address: devnet!.factory,
      abi: gianoSmartWalletFactoryAbi,
      functionName: 'createAccount',
      args: [owners, 0n],
    });
    await client.waitForTransactionReceipt({ hash });
    return predicted;
  }

  /**
   * Asks the service for an authorisation, then submits the operation through the EntryPoint.
   *
   * The order mirrors production exactly: the sponsorship goes in first, and the account signature
   * is taken over the whole operation *including* it — which is what makes the two signatures
   * mutually binding.
   */
  async function sendSponsoredOp(callData: Hex): Promise<{ userOpHash: Hex; feeWei: bigint; serviceHash?: Hex }> {
    const nonce = (await client.readContract({
      address: ENTRY_POINT,
      abi: ENTRY_POINT_ABI,
      functionName: 'getNonce',
      args: [walletAddress, 0n],
    })) as bigint;

    const callGasLimit = 300_000n;
    const verificationGasLimit = 600_000n;
    const preVerificationGas = 60_000n;
    const maxPriorityFeePerGas = 1_000_000_000n;
    const maxFeePerGas = 2_000_000_000n;
    const paymasterVerificationGasLimit = 200_000n;
    const paymasterPostOpGasLimit = 150_000n;

    const outcome = await service.decide({
      method: 'data',
      session,
      nonce,
      accountGasLimits: packUints(verificationGasLimit, callGasLimit),
      gasFees: packUints(maxPriorityFeePerGas, maxFeePerGas),
      candidate: {
        sender: walletAddress,
        callData,
        callGasLimit,
        verificationGasLimit,
        preVerificationGas,
        maxFeePerGas,
        paymasterVerificationGasLimit,
        paymasterPostOpGasLimit,
      },
    });

    if (outcome.outcome !== 'allowed') {
      throw new Error(`the service refused: ${outcome.reason} — ${outcome.message}`);
    }

    const op = {
      sender: walletAddress,
      nonce,
      initCode: '0x' as Hex,
      callData,
      accountGasLimits: packUints(verificationGasLimit, callGasLimit),
      preVerificationGas,
      gasFees: packUints(maxPriorityFeePerGas, maxFeePerGas),
      paymasterAndData: (`${outcome.paymaster}${paymasterVerificationGasLimit.toString(16).padStart(32, '0')}${paymasterPostOpGasLimit
        .toString(16)
        .padStart(32, '0')}${outcome.paymasterData.slice(2)}`) as Hex,
      signature: '0x' as Hex,
    };

    const userOpHash = (await client.readContract({
      address: ENTRY_POINT,
      abi: ENTRY_POINT_ABI,
      functionName: 'getUserOpHash',
      args: [op],
    })) as Hex;

    const raw = await owner.sign({ hash: userOpHash });
    op.signature = encodeAbiParameters(
      [{ type: 'tuple', components: [{ name: 'ownerBytes', type: 'bytes' }, { name: 'signatureData', type: 'bytes' }] }],
      [{ ownerBytes: encodeAbiParameters([{ type: 'address' }], [owner.address]), signatureData: raw }],
    );

    const wallet = createWalletClient({ account: bundler, chain: { ...foundry, id: CHAIN_ID }, transport: http(RPC_URL) });
    const hash = await wallet.writeContract({
      address: ENTRY_POINT,
      abi: ENTRY_POINT_ABI,
      functionName: 'handleOps',
      args: [[op], bundler.address],
    });
    const receipt = await client.waitForTransactionReceipt({ hash });
    expect(receipt.status).toBe('success');

    return { userOpHash, feeWei: outcome.feeWei, serviceHash: outcome.useropHash };
  }

  const erc20Transfer = (): Hex =>
    encodeFunctionData({
      abi: gianoSmartWalletAbi,
      functionName: 'execute',
      args: [
        devnet!.testErc20,
        0n,
        // transfer(address,uint256) to self, zero tokens: valid, not meaningful
        `0xa9059cbb${walletAddress.slice(2).toLowerCase().padStart(64, '0')}${'0'.repeat(64)}` as Hex,
      ],
    });

  // ───────────────────────────────────────────────────────────────────────────

  /**
   * The whole basis of settlement matching. `Sponsored` carries the operation's hash and not its
   * nonce, so if the service's own computation of that hash disagreed with the EntryPoint's by even
   * one byte, no reservation would ever be settled — every tenant's balance would look permanently
   * spent until each reservation timed out.
   */
  it("computes the same operation hash the EntryPoint does", async () => {
    const { userOpHash, serviceHash } = await sendSponsoredOp(erc20Transfer());
    expect(serviceHash).toBe(userOpHash);
  }, 60_000);

  it('reconciles the on-chain balance into the ledger without replaying events', async () => {
    const view = await ledger.getBalanceView(tenantId, CHAIN_ID);
    expect(view.balanceWei, 'the balance must come from the contract, not from an event lookback').toBeGreaterThan(0n);
    expect(view.deficitWei).toBe(0n);
  });

  it('sponsors an operation the contract then settles against the right tenant', async () => {
    const before = await paymaster.tenant(`0x${tenantId.replace(/-/g, '')}`);
    const treasuryBefore = await paymaster.treasury();
    const depositBefore = await paymaster.deposit();

    const { userOpHash, feeWei } = await sendSponsoredOp(erc20Transfer());

    const after = await paymaster.tenant(`0x${tenantId.replace(/-/g, '')}`);

    // The tenant paid, and nothing else did.
    expect(after.balanceWei).toBeLessThan(before.balanceWei);
    expect(after.deficitWei).toBe(0n);
    // The fee, and only the fee, reached the treasury.
    expect(await paymaster.treasury()).toBe(treasuryBefore + feeWei);

    // D1's direction: the ledger must fall at least as fast as the deposit.
    const depositDrop = depositBefore - (await paymaster.deposit());
    const ledgerDrop = before.balanceWei - after.balanceWei;
    expect(ledgerDrop).toBeGreaterThanOrEqual(depositDrop);

    // And the invariant holds.
    expect(after.balanceWei + (await paymaster.treasury())).toBeLessThanOrEqual(await paymaster.deposit());
    void userOpHash;
  }, 120_000);

  it('settles the reservation and records the breakdown when the watcher observes the event', async () => {
    const { userOpHash, feeWei } = await sendSponsoredOp(erc20Transfer());

    await watcher.pollOnce();

    const [settlement] = await db
      .select()
      .from(sponsorshipSettlements)
      .where(and(eq(sponsorshipSettlements.chainId, CHAIN_ID), eq(sponsorshipSettlements.useropHash, userOpHash)));

    expect(settlement, 'the watcher did not record this settlement').toBeDefined();
    expect(settlement.tenantId).toBe(tenantId);
    expect(settlement.success).toBe(true);
    // R-43: gas, fee and overhead separately visible, and summing to the total.
    expect(BigInt(settlement.gasCostWei)).toBeGreaterThan(0n);
    expect(BigInt(settlement.feeWei)).toBe(feeWei);
    expect(BigInt(settlement.overheadWei)).toBeGreaterThan(0n);
    expect(BigInt(settlement.totalWei)).toBe(
      BigInt(settlement.gasCostWei) + BigInt(settlement.feeWei) + BigInt(settlement.overheadWei),
    );

    // The reservation is released, so the funds are available again rather than held for the TTL.
    const view = await ledger.getBalanceView(tenantId, CHAIN_ID);
    expect(view.reservedWei).toBe(0n);

    // And the cached balance agrees with the chain.
    const onChain = await paymaster.tenant(`0x${tenantId.replace(/-/g, '')}`);
    const [row] = await db
      .select()
      .from(paymasterTenants)
      .where(and(eq(paymasterTenants.tenantId, tenantId), eq(paymasterTenants.chainId, CHAIN_ID)));
    expect(BigInt(row.balanceWei)).toBe(onChain.balanceWei);
  }, 120_000);

  it('is idempotent: re-polling the same logs changes nothing', async () => {
    await watcher.pollOnce();
    const before = await db.select().from(sponsorshipSettlements);

    // Rewind the cursor so the same logs are seen again, exactly as a reorg would.
    await db.execute(
      `UPDATE paymaster_state SET last_synced_block = 0 WHERE chain_id = ${CHAIN_ID}` as never,
    );
    await watcher.pollOnce();

    const after = await db.select().from(sponsorshipSettlements);
    expect(after.length).toBe(before.length);
  }, 120_000);

  it('keeps the invariant intact and the slack positive after real settlements', async () => {
    const result = await watcher.reconcileOnce();
    expect(result.breach).toBe(false);
    expect(result.slackWei).toBeGreaterThan(0n);
    expect(result.divergenceWei).toBe(0n);
  }, 60_000);

  it('refuses an operation for a contract the tenant does not allow-list', async () => {
    const callData = encodeFunctionData({
      abi: gianoSmartWalletAbi,
      functionName: 'execute',
      args: ['0x000000000000000000000000000000000000dEaD', 0n, '0xa9059cbb'],
    });
    await expect(sendSponsoredOp(callData)).rejects.toThrow(/contract-not-allowed/);
  }, 60_000);
});
