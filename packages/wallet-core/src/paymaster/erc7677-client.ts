import type { Address, Hex } from 'viem';
import { GianoError } from '../giano-error';
import { defaultGianoLogger, type GianoLogger } from '../logger';
import {
  REFUSAL_CODE_TO_REASON,
  SponsorshipRefusedError,
  isSponsorshipRefusalReason,
  type SponsorshipRefusalReason,
  type SponsorshipRuleResult,
} from './refusal';

/**
 * ERC-7677 client for the Giano sponsorship service.
 *
 * `getPaymasterStubData` and `getPaymasterData` are shaped the way viem's
 * `createBundlerClient({ paymaster })` already expects, so wiring sponsorship in is a config
 * change rather than a provider change.
 *
 * `checkSponsorship` is the third method and the reason this client is not just a transport: on
 * the wallet's review screen a refusal is an *expected outcome*, not an error, and the screen has
 * to know about it before it renders an approve button (R-15). It issues the same stub request and
 * returns the refusal as a value.
 */

export type Erc7677PaymasterClientOptions = {
  /** The service endpoint, e.g. `/api/v1/paymaster`. */
  url: string;
  /** The chain the wallet is operating on. Sent for validation; the server does not trust it. */
  chainId: number;
  /** Current wallet session bearer, or null when signed out. */
  getSessionToken: () => string | null;
  /** EntryPoint address; defaults to the v0.7 canonical address. */
  entryPointAddress?: Address;
  logger?: GianoLogger;
  /** Injected for tests. */
  fetchImpl?: typeof fetch;
};

/** The subset of a UserOperation the service needs, as viem hands it to a paymaster hook. */
export type PaymasterUserOperation = {
  sender: Address;
  nonce: bigint;
  callData: Hex;
  callGasLimit?: bigint;
  verificationGasLimit?: bigint;
  preVerificationGas?: bigint;
  maxFeePerGas?: bigint;
  maxPriorityFeePerGas?: bigint;
  factory?: Address;
  factoryData?: Hex;
};

export type PaymasterResult = {
  paymaster: Address;
  paymasterData: Hex;
  paymasterVerificationGasLimit?: bigint;
  paymasterPostOpGasLimit?: bigint;
};

export type SponsorshipCheck =
  | { sponsored: true; paymaster: Address; feeWei?: bigint }
  | { sponsored: false; reason: SponsorshipRefusalReason; message: string; retryable: boolean; ruleResults: SponsorshipRuleResult[] };

/**
 * How the paymaster hooks are called.
 *
 * viem's `prepareUserOperation` **spreads** the operation's fields at the top level alongside
 * `chainId` and `entryPointAddress`; `checkSponsorship` is called by our own code with the operation
 * nested. Both are accepted, because getting this wrong is invisible until a real bundler client
 * drives it: a unit test that passes the shape the implementation expects proves nothing about the
 * shape viem actually sends.
 */
export type PaymasterHookParams =
  | (PaymasterUserOperation & { chainId?: number; entryPointAddress?: Address; context?: unknown })
  | { userOperation: PaymasterUserOperation };

export type Erc7677PaymasterClient = {
  getPaymasterStubData: (params: PaymasterHookParams) => Promise<PaymasterResult>;
  getPaymasterData: (params: PaymasterHookParams) => Promise<PaymasterResult>;
  checkSponsorship: (params: PaymasterHookParams) => Promise<SponsorshipCheck>;
};

function toUserOperation(params: PaymasterHookParams): PaymasterUserOperation {
  const nested = (params as { userOperation?: PaymasterUserOperation }).userOperation;
  const op = nested ?? (params as PaymasterUserOperation);
  if (!op || typeof op.sender !== 'string') {
    throw new GianoError(
      'the paymaster hook was called without a user operation. Expected either the fields spread at ' +
        'the top level (viem) or nested under `userOperation`.',
    );
  }
  return op;
}

const ENTRY_POINT_V07: Address = '0x0000000071727De22E5E9d8BAf0edAc6f37da032';

/** ERC-7677 speaks hex quantities, not JSON numbers, and `undefined` must not become `"0x0"`. */
function toQuantity(value: bigint | undefined): Hex | undefined {
  return value === undefined ? undefined : (`0x${value.toString(16)}` as Hex);
}

function fromQuantity(value: unknown): bigint | undefined {
  if (typeof value !== 'string') return undefined;
  return BigInt(value);
}

function serialiseUserOperation(op: PaymasterUserOperation): Record<string, unknown> {
  const serialised: Record<string, unknown> = {
    sender: op.sender,
    nonce: toQuantity(op.nonce),
    callData: op.callData,
  };
  const optional: Array<[string, bigint | undefined]> = [
    ['callGasLimit', op.callGasLimit],
    ['verificationGasLimit', op.verificationGasLimit],
    ['preVerificationGas', op.preVerificationGas],
    ['maxFeePerGas', op.maxFeePerGas],
    ['maxPriorityFeePerGas', op.maxPriorityFeePerGas],
  ];
  for (const [key, value] of optional) {
    const quantity = toQuantity(value);
    if (quantity !== undefined) serialised[key] = quantity;
  }
  if (op.factory) {
    serialised.factory = op.factory;
    serialised.factoryData = op.factoryData;
  }
  return serialised;
}

type JsonRpcError = { code: number; message: string; data?: { reason?: string; ruleResults?: SponsorshipRuleResult[] } };

/** Maps a JSON-RPC error onto a typed refusal, preferring `data.reason` over the numeric code. */
function toRefusal(error: JsonRpcError): SponsorshipRefusedError {
  const fromData = error.data?.reason;
  const reason: SponsorshipRefusalReason = isSponsorshipRefusalReason(fromData)
    ? fromData
    : (REFUSAL_CODE_TO_REASON[error.code] ?? 'temporarily-unavailable');

  return new SponsorshipRefusedError(error.message || `sponsorship refused: ${reason}`, {
    reason,
    code: error.code,
    ruleResults: error.data?.ruleResults,
  });
}

export function createErc7677PaymasterClient(options: Erc7677PaymasterClientOptions): Erc7677PaymasterClient {
  const logger = options.logger ?? defaultGianoLogger;
  const doFetch = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
  const entryPoint = options.entryPointAddress ?? ENTRY_POINT_V07;
  let nextId = 1;

  async function call(method: 'pm_getPaymasterStubData' | 'pm_getPaymasterData', op: PaymasterUserOperation): Promise<PaymasterResult> {
    const token = options.getSessionToken();
    if (!token) {
      // R-11. Without a session the service has nothing to bind the request to, and there is no
      // point spending a round trip to be told so.
      throw new SponsorshipRefusedError('sponsorship requires a signed-in wallet session', {
        reason: 'not-your-wallet',
        code: -32009,
      });
    }

    // Built outside the try: a serialisation bug here is a bug in this client, and reporting it as
    // "the service could not be reached" would send whoever is debugging it to the wrong place.
    const requestBody = JSON.stringify({
      jsonrpc: '2.0',
      id: nextId++,
      method,
      params: [serialiseUserOperation(op), entryPoint, `0x${options.chainId.toString(16)}`, {}],
    });

    let response: Response;
    try {
      response = await doFetch(options.url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
        body: requestBody,
      });
    } catch (cause) {
      // A transport failure is an outage, never a rule refusal (R-21). The cause is kept on the
      // error so the real network failure is still recoverable from a log.
      throw new SponsorshipRefusedError(
        `the sponsorship service could not be reached: ${cause instanceof Error ? cause.message : String(cause)}`,
        { reason: 'temporarily-unavailable', code: -32011, cause },
      );
    }

    if (response.status === 401 || response.status === 403) {
      throw new SponsorshipRefusedError('the wallet session was rejected by the sponsorship service', {
        reason: 'not-your-wallet',
        code: -32009,
      });
    }

    let body: { result?: unknown; error?: JsonRpcError };
    try {
      body = (await response.json()) as typeof body;
    } catch (cause) {
      throw new SponsorshipRefusedError('the sponsorship service returned a malformed response', {
        reason: 'temporarily-unavailable',
        code: -32011,
        cause,
      });
    }

    if (body.error) throw toRefusal(body.error);
    if (!response.ok) {
      throw new SponsorshipRefusedError(`the sponsorship service returned ${response.status}`, {
        reason: 'temporarily-unavailable',
        code: -32011,
      });
    }

    const result = body.result as Record<string, unknown> | undefined;
    if (!result || typeof result.paymaster !== 'string' || typeof result.paymasterData !== 'string') {
      throw new GianoError('the sponsorship service returned no paymaster data');
    }

    return {
      paymaster: result.paymaster as Address,
      paymasterData: result.paymasterData as Hex,
      paymasterVerificationGasLimit: fromQuantity(result.paymasterVerificationGasLimit),
      paymasterPostOpGasLimit: fromQuantity(result.paymasterPostOpGasLimit),
    };
  }

  return {
    // `async` rather than a plain arrow so a malformed call *rejects* instead of throwing
    // synchronously — viem awaits these, and a synchronous throw escapes its error handling.
    async getPaymasterStubData(params) {
      return call('pm_getPaymasterStubData', toUserOperation(params));
    },

    async getPaymasterData(params) {
      return call('pm_getPaymasterData', toUserOperation(params));
    },

    async checkSponsorship(params) {
      try {
        const result = await call('pm_getPaymasterStubData', toUserOperation(params));
        logger.debug('sponsorship available', { paymaster: result.paymaster });
        return { sponsored: true, paymaster: result.paymaster };
      } catch (error) {
        if (error instanceof SponsorshipRefusedError) {
          logger.debug('sponsorship refused', { reason: error.reason });
          return {
            sponsored: false,
            reason: error.reason,
            message: error.message,
            retryable: error.retryable,
            ruleResults: error.ruleResults,
          };
        }
        throw error;
      }
    },
  };
}
