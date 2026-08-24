import { and, eq } from 'drizzle-orm';
import type { Address, Hex } from 'viem';
import type { Db } from '../db/index.js';
import { sponsorshipDecisions, tenantSponsorship } from '../db/schema.js';
import {
  computeUserOpHash,
  encodePaymasterAndData,
  encodePaymasterData,
  encodeStubPaymasterData,
  tenantIdToBytes16,
  type PaymasterReader,
} from './paymaster-contract.js';
import type { SessionContext } from './sessions.js';
import { DENY_ALL_SPONSORSHIP, parseSponsorshipConfig, type SponsorshipConfig } from './sponsorship-config.js';
import type { LedgerService } from './sponsorship-ledger.js';
import {
  computeMaxCost,
  computeOverheadBound,
  evaluateSponsorship,
  type CandidateOperation,
  type SponsorshipRefusalReason,
  type SponsorshipRuleResult,
} from './sponsorship-rules.js';
import type { SponsorshipSigner } from './sponsorship-signer.js';

/**
 * The sponsorship decision, end to end.
 *
 * Two entry points, and the difference between them is the whole design:
 *
 *   `stub` evaluates the rules and reads the balance, and reserves nothing. It runs during gas
 *   estimation, possibly repeatedly, and it is also what the wallet's review screen calls before
 *   it renders an approve button — so a refusal reaches the user *before* they are asked for a
 *   fingerprint, and estimation noise never fills the reservation ledger.
 *
 *   `data` re-evaluates authoritatively, reserves atomically, and signs. It runs once, immediately
 *   before the user's passkey signature, which puts the reservation strictly before the moment the
 *   user can commit.
 */

export type SponsorshipMethod = 'stub' | 'data';

export type SponsorshipRequest = {
  method: SponsorshipMethod;
  session: SessionContext;
  candidate: CandidateOperation;
  nonce: bigint;
  /** Packed as the EntryPoint packs them, because the authorisation signs them in that form. */
  accountGasLimits: Hex;
  gasFees: Hex;
};

export type SponsorshipSuccess = {
  outcome: 'allowed';
  paymaster: Address;
  paymasterData: Hex;
  paymasterVerificationGasLimit: bigint;
  paymasterPostOpGasLimit: bigint;
  feeWei: bigint;
  /**
   * The hash the operation will have on chain. Present only for a real authorisation: a stub's
   * dummy signature gives a hash the submitted operation will not have, and returning that would
   * be worse than returning nothing.
   */
  useropHash?: Hex;
  decisionId: string;
};

export type SponsorshipRefusal = {
  outcome: 'refused';
  reason: SponsorshipRefusalReason | 'temporarily-unavailable';
  message: string;
  ruleResults: SponsorshipRuleResult[];
  decisionId?: string;
};

export type SponsorshipOutcome = SponsorshipSuccess | SponsorshipRefusal;

export type SponsorshipServiceOptions = {
  db: Db;
  chainId: number;
  paymaster: PaymasterReader;
  ledger: LedgerService;
  signer: SponsorshipSigner;
  /** `validUntil` window. Minutes, not hours: an authorisation is a commitment of real money. */
  validitySeconds: number;
  /** Deliberately longer than the validity window, so a reservation outlives its authorisation. */
  reservationTtlSeconds: number;
  /**
   * The platform's cap on a single wallet-management operation.
   *
   * Platform configuration rather than the tenant's, because wallet management is sponsored
   * whatever a tenant's allowlist says — so this is the bound on the one spend path a tenant
   * cannot close.
   */
  walletManagementCapWei: bigint;
  /** The EntryPoint this service authorises for. Part of the operation's hash. */
  entryPoint: Address;
  /** Flips issuance off immediately, without a restart. The first response to a suspected compromise. */
  isEmergencyStopped: () => boolean;
  onDecision?: (event: {
    tenantId: string;
    method: SponsorshipMethod;
    outcome: 'allowed' | 'refused';
    reason?: string;
    keyId?: string;
  }) => void;
  now?: () => number;
};

export type SponsorshipService = {
  decide: (request: SponsorshipRequest) => Promise<SponsorshipOutcome>;
  getConfig: (tenantId: string) => Promise<{ config: SponsorshipConfig; unparseable: boolean }>;
  health: () => Promise<'ok' | 'unavailable'>;
};

export function createSponsorshipService(options: SponsorshipServiceOptions): SponsorshipService {
  const { db, chainId, paymaster, ledger, signer } = options;
  const now = options.now ?? (() => Date.now());

  async function getConfig(tenantId: string): Promise<{ config: SponsorshipConfig; unparseable: boolean }> {
    const [row] = await db
      .select({ config: tenantSponsorship.config })
      .from(tenantSponsorship)
      .where(and(eq(tenantSponsorship.tenantId, tenantId), eq(tenantSponsorship.chainId, chainId)));

    // No row at all is not a broken configuration — it is a tenant that has not configured
    // sponsorship, which is the correct default and gets the "switched off" reason rather than
    // the "your configuration is broken" one.
    if (!row) return { config: DENY_ALL_SPONSORSHIP, unparseable: false };

    const parsed = parseSponsorshipConfig(row.config);
    return { config: parsed.config, unparseable: !parsed.ok };
  }

  async function recordDecision(args: {
    session: SessionContext;
    method: SponsorshipMethod;
    sender: string;
    outcome: 'allowed' | 'refused';
    reason?: string;
    ruleResults: SponsorshipRuleResult[];
    feeWei?: bigint;
    reservationId?: string;
    useropHash?: string;
  }): Promise<string> {
    const [row] = await db
      .insert(sponsorshipDecisions)
      .values({
        tenantId: args.session.tenantId,
        chainId,
        userId: args.session.userId,
        sessionId: args.session.sessionId,
        method: args.method,
        sender: args.sender.toLowerCase(),
        outcome: args.outcome,
        reason: args.reason,
        ruleResults: args.ruleResults,
        feeWei: args.feeWei?.toString(),
        reservationId: args.reservationId,
        useropHash: args.useropHash,
      })
      .returning({ id: sponsorshipDecisions.id });

    options.onDecision?.({
      tenantId: args.session.tenantId,
      method: args.method,
      outcome: args.outcome,
      reason: args.reason,
    });
    return row.id;
  }

  async function refuse(args: {
    session: SessionContext;
    method: SponsorshipMethod;
    sender: string;
    reason: SponsorshipRefusalReason | 'temporarily-unavailable';
    message: string;
    ruleResults: SponsorshipRuleResult[];
    feeWei?: bigint;
  }): Promise<SponsorshipRefusal> {
    const decisionId = await recordDecision({ ...args, outcome: 'refused' });
    return { outcome: 'refused', reason: args.reason, message: args.message, ruleResults: args.ruleResults, decisionId };
  }

  return {
    getConfig,

    health: () => signer.health(),

    async decide(request) {
      const { session, candidate, method } = request;
      const tenantId = tenantIdToBytes16(session.tenantId);

      // The deployment-wide stop comes first: when it is on, nothing about a particular tenant or
      // operation should be able to produce a signature.
      if (options.isEmergencyStopped()) {
        return refuse({
          session,
          method,
          sender: candidate.sender,
          reason: 'temporarily-unavailable',
          message: 'sponsorship is temporarily unavailable',
          ruleResults: [{ rule: 'emergency-stop', passed: false, detail: 'issuance is stopped deployment-wide' }],
        });
      }

      // Anything read from the chain can fail, and a chain read failing is an outage — never a
      // rule refusal. Conflating the two would have the wallet tell a user their app does not
      // support this contract when in fact the RPC is down.
      let onChain: { postOpGasAllowance: bigint; penaltyBps: bigint };
      let feeWei: bigint;
      try {
        const [params, fee] = await Promise.all([paymaster.params(), paymaster.feeFor(tenantId)]);
        onChain = params;
        feeWei = fee;
      } catch (error) {
        return refuse({
          session,
          method,
          sender: candidate.sender,
          reason: 'temporarily-unavailable',
          message: 'the paymaster could not be read',
          ruleResults: [{ rule: 'paymaster-reachable', passed: false, detail: (error as Error).message }],
        });
      }

      const { config, unparseable } = await getConfig(session.tenantId);
      const balance = await ledger.getBalanceView(session.tenantId, chainId);

      const decision = evaluateSponsorship({
        candidate,
        config,
        balance,
        feeWei,
        overhead: onChain,
        walletManagementCapWei: options.walletManagementCapWei,
        sessionWalletAddress: session.walletAddress as Address,
        configUnparseable: unparseable,
      });

      if (!decision.allowed) {
        return refuse({
          session,
          method,
          sender: candidate.sender,
          reason: decision.reason!,
          message: decision.detail ?? 'sponsorship refused',
          ruleResults: decision.results,
          feeWei,
        });
      }

      const validAfter = 0;
      const validUntil = Math.floor(now() / 1000) + options.validitySeconds;

      // The stub call reserves nothing and signs nothing. It runs during estimation, possibly
      // several times per transaction, and reserving there would fill the ledger with claims for
      // operations the user never approved.
      if (method === 'stub') {
        const decisionId = await recordDecision({
          session,
          method,
          sender: candidate.sender,
          outcome: 'allowed',
          ruleResults: decision.results,
          feeWei,
        });
        return {
          outcome: 'allowed',
          paymaster: paymaster.address,
          paymasterData: encodeStubPaymasterData({
            tenantId,
            validUntil,
            validAfter,
            feeWei,
            // A plausible-looking dummy: the real signer's address is not a secret, but the stub
            // must not be mistaken for an authorisation, and a zero signature never verifies.
            signer: await signer.address(),
          }),
          paymasterVerificationGasLimit: candidate.paymasterVerificationGasLimit,
          paymasterPostOpGasLimit: candidate.paymasterPostOpGasLimit,
          feeWei,
          decisionId,
        };
      }

      // From here on real money is at stake, so the order is: reserve, then sign. Signing first
      // would leave an authorisation in the wild that no reservation covers.
      const reservation = await ledger.reserve({
        tenantId: session.tenantId,
        chainId,
        sender: candidate.sender,
        nonce: request.nonce,
        maxCostWei: computeMaxCost(candidate),
        feeWei,
        overheadWei: computeOverheadBound(candidate, onChain),
        ttlSeconds: options.reservationTtlSeconds,
      });

      if (!reservation.reserved) {
        // The rules engine said the balance was sufficient a moment ago and the ledger disagrees,
        // which means a concurrent request took the room in between. That is exactly the case the
        // reservation ledger exists to catch, and refusing here is what stops the collective
        // overdraw the chain could not undo.
        const cause =
          reservation.cause === 'duplicate-in-flight'
            ? 'an authorisation for this operation is already in flight'
            : 'another operation reserved the remaining balance first';
        return refuse({
          session,
          method,
          sender: candidate.sender,
          reason: 'insufficient-balance',
          message: cause,
          ruleResults: [...decision.results, { rule: 'reserve', passed: false, detail: cause }],
          feeWei,
        });
      }

      let signature: Hex;
      try {
        signature = await signer.signAuthorisation({
          chainId,
          paymaster: paymaster.address,
          sender: candidate.sender,
          nonce: request.nonce,
          callData: candidate.callData,
          accountGasLimits: request.accountGasLimits,
          preVerificationGas: candidate.preVerificationGas,
          gasFees: request.gasFees,
          paymasterVerificationGasLimit: candidate.paymasterVerificationGasLimit,
          paymasterPostOpGasLimit: candidate.paymasterPostOpGasLimit,
          tenantId,
          validUntil,
          validAfter,
          feeWei,
        });
      } catch (error) {
        // Release immediately rather than letting the TTL run: a signing failure that held the
        // tenant's funds for minutes would be indistinguishable from having spent them.
        await ledger.release(reservation.id);
        return refuse({
          session,
          method,
          sender: candidate.sender,
          reason: 'temporarily-unavailable',
          message: 'the sponsorship signer is unavailable',
          ruleResults: [...decision.results, { rule: 'sign', passed: false, detail: (error as Error).message }],
          feeWei,
        });
      }

      const paymasterData = encodePaymasterData({
        tenantId,
        validUntil,
        validAfter,
        feeWei,
        signer: await signer.address(),
        signature,
      });

      /*
       * The operation's hash, recorded against the reservation.
       *
       * It is computable here — the hash covers `paymasterAndData` but not the account signature,
       * so it is fixed the moment the authorisation is signed. Recording it is what lets the
       * watcher settle this reservation when it sees the matching `Sponsored` event: that event
       * carries the hash and not the nonce, so without this every reservation would sit untouched
       * until its TTL expired, with the tenant's balance looking spent the whole time.
       */
      const useropHash = computeUserOpHash({
        sender: candidate.sender,
        nonce: request.nonce,
        initCode: candidate.factory ? `${candidate.factory}${(candidate.factoryData ?? '0x').slice(2)}` : '0x',
        callData: candidate.callData,
        accountGasLimits: request.accountGasLimits,
        preVerificationGas: candidate.preVerificationGas,
        gasFees: request.gasFees,
        paymasterAndData: encodePaymasterAndData({
          paymaster: paymaster.address,
          paymasterVerificationGasLimit: candidate.paymasterVerificationGasLimit,
          paymasterPostOpGasLimit: candidate.paymasterPostOpGasLimit,
          paymasterData,
        }),
        entryPoint: options.entryPoint,
        chainId,
      });
      await ledger.attachUseropHash(reservation.id, useropHash);

      const decisionId = await recordDecision({
        session,
        method,
        sender: candidate.sender,
        outcome: 'allowed',
        ruleResults: decision.results,
        feeWei,
        reservationId: reservation.id,
        useropHash,
      });

      options.onDecision?.({
        tenantId: session.tenantId,
        method,
        outcome: 'allowed',
        keyId: signer.keyId,
      });

      return {
        outcome: 'allowed',
        paymaster: paymaster.address,
        paymasterData,
        paymasterVerificationGasLimit: candidate.paymasterVerificationGasLimit,
        paymasterPostOpGasLimit: candidate.paymasterPostOpGasLimit,
        feeWei,
        useropHash,
        decisionId,
      };
    },
  };
}

/** Packs two 128-bit values the way the EntryPoint does, because the signature covers that form. */
export function packUints(high: bigint, low: bigint): Hex {
  return `0x${(high << 128n | low).toString(16).padStart(64, '0')}`;
}
