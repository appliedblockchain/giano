import { GianoError } from '../giano-error';

/**
 * Why a sponsorship request was refused.
 *
 * These are the stable, machine-readable reasons the wallet keys its copy off (R-16). Never key UI
 * behaviour off the message: the message is for humans and may be reworded, the reason may not.
 *
 * The distinction that matters most is between the rule refusals and
 * `sponsorship-temporarily-unavailable`: the sponsorship service is on the critical path for
 * transacting, so an outage must be legible as an outage rather than as a misconfiguration (R-21).
 */
export const SPONSORSHIP_REFUSAL_REASONS = [
  'sponsorship-disabled',
  'no-sponsorship-config',
  'contract-not-allowed',
  'function-not-allowed',
  'wallet-management-not-sponsored',
  'cost-exceeds-cap',
  'insufficient-balance',
  'tenant-in-deficit',
  'not-your-wallet',
  'chain-or-entrypoint-mismatch',
  'temporarily-unavailable',
] as const;

export type SponsorshipRefusalReason = (typeof SPONSORSHIP_REFUSAL_REASONS)[number];

/** JSON-RPC error code → reason, mirroring §5.4 of the paymaster specification. */
export const REFUSAL_CODE_TO_REASON: Record<number, SponsorshipRefusalReason> = {
  [-32001]: 'sponsorship-disabled',
  [-32002]: 'no-sponsorship-config',
  [-32003]: 'contract-not-allowed',
  [-32004]: 'function-not-allowed',
  [-32005]: 'wallet-management-not-sponsored',
  [-32006]: 'cost-exceeds-cap',
  [-32007]: 'insufficient-balance',
  [-32008]: 'tenant-in-deficit',
  [-32009]: 'not-your-wallet',
  [-32010]: 'chain-or-entrypoint-mismatch',
  [-32011]: 'temporarily-unavailable',
};

/** Reasons worth trying again — the rest are settled facts about this transaction. */
const RETRYABLE: ReadonlySet<SponsorshipRefusalReason> = new Set<SponsorshipRefusalReason>([
  'insufficient-balance',
  'tenant-in-deficit',
  'temporarily-unavailable',
]);

export function isRetryableRefusal(reason: SponsorshipRefusalReason): boolean {
  return RETRYABLE.has(reason);
}

export function isSponsorshipRefusalReason(value: unknown): value is SponsorshipRefusalReason {
  return typeof value === 'string' && (SPONSORSHIP_REFUSAL_REASONS as readonly string[]).includes(value);
}

/** One rule's verdict, mirroring the relay's `PolicyRuleResult` so both read alike. */
export type SponsorshipRuleResult = {
  rule: string;
  passed: boolean;
  detail?: string;
};

export class SponsorshipRefusedError extends GianoError {
  readonly reason: SponsorshipRefusalReason;
  readonly code: number;
  readonly retryable: boolean;
  readonly ruleResults: SponsorshipRuleResult[];

  constructor(
    message: string,
    args: { reason: SponsorshipRefusalReason; code: number; ruleResults?: SponsorshipRuleResult[]; cause?: unknown },
  ) {
    super(message, { cause: args.cause });
    this.reason = args.reason;
    this.code = args.code;
    this.retryable = isRetryableRefusal(args.reason);
    this.ruleResults = args.ruleResults ?? [];
  }
}
