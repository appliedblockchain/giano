import { z } from 'zod';

/**
 * Versioned message envelope for the Giano popup transport, modeled on the
 * keys.coinbase.com postMessage pattern: every message is `{giano, id, type, payload}`,
 * zod-validated in BOTH directions, and only ever exchanged between the pinned dApp
 * origin and the wallet origin.
 */

export const PROTOCOL_VERSION = 1 as const;

export const rpcErrorSchema = z.object({
  code: z.number().int(),
  message: z.string(),
  data: z.unknown().optional(),
});
export type RpcError = z.infer<typeof rpcErrorSchema>;

const base = {
  giano: z.literal(PROTOCOL_VERSION),
  id: z.string().min(10).max(64),
};

/** Popup page finished loading its transport host — sent to opener before origins are pinned. */
export const readyMessageSchema = z.object({ ...base, type: z.literal('ready') });

/**
 * dApp → wallet: start a session; carries SDK version, requested capabilities and the
 * chain the dApp will transact on. `chainId` is REQUIRED: naming the chain is mandatory
 * and there is no default chain anywhere in the system (MC-11). A handshake without one
 * is refused with `handshake:nack { reason: 'chain-required' }` — this is a breaking
 * protocol change, affordable exactly once because nothing is deployed (MC-148).
 */
export const handshakeMessageSchema = z.object({
  ...base,
  type: z.literal('handshake'),
  payload: z.object({
    sdkVersion: z.string(),
    capabilities: z.array(z.string()).default([]),
    /** The chain the dApp will transact on, fixed for the life of the session (MC-01, MC-02). */
    chainId: z.number().int().positive().optional(),
  }),
});

/**
 * wallet → dApp: session accepted; carries wallet version, granted capabilities, the chain
 * GRANTED for this session (always equal to the requested one — a mismatch is a nack, not
 * an ack) and every chain this wallet origin serves (MC-05).
 */
export const handshakeAckMessageSchema = z.object({
  ...base,
  type: z.literal('handshake:ack'),
  payload: z.object({
    walletVersion: z.string(),
    capabilities: z.array(z.string()).default([]),
    chainId: z.number().int().positive(),
    supportedChainIds: z.array(z.number().int().positive()),
  }),
});

/**
 * wallet → dApp: the handshake was REFUSED — distinct from `close`, which is teardown.
 * `supportedChainIds` is present for 'unsupported-chain' and 'chain-required', so an
 * integrator can diagnose a refusal without access to the wallet origin's configuration
 * (MC-04). There is deliberately no other endpoint enumerating served chains (MC-13).
 */
export const handshakeNackMessageSchema = z.object({
  ...base,
  type: z.literal('handshake:nack'),
  payload: z.object({
    reason: z.enum(['unsupported-chain', 'chain-required', 'origin-not-allowed', 'protocol-version']),
    message: z.string(),
    supportedChainIds: z.array(z.number().int().positive()).optional(),
  }),
});

/** dApp → wallet: EIP-1193 request. */
export const rpcMessageSchema = z.object({
  ...base,
  type: z.literal('rpc'),
  payload: z.object({
    method: z.string().min(1),
    params: z.unknown().optional(),
  }),
});

/** wallet → dApp: response for the rpc message with the same id. */
export const rpcResponseMessageSchema = z.object({
  ...base,
  type: z.literal('rpc:response'),
  // NOT a union: z.unknown() makes `result` effectively optional, so an error payload
  // would happily parse as the result branch. A single object + explicit error check
  // keeps the wire format unambiguous.
  payload: z.object({ result: z.unknown().optional(), error: rpcErrorSchema.optional() }),
});

/** wallet → dApp: EIP-1193 event (accountsChanged, chainChanged, disconnect, …). */
export const eventMessageSchema = z.object({
  ...base,
  type: z.literal('event'),
  payload: z.object({
    event: z.string().min(1),
    data: z.unknown().optional(),
  }),
});

/** either direction: session teardown. */
export const closeMessageSchema = z.object({ ...base, type: z.literal('close') });

export const transportMessageSchema = z.discriminatedUnion('type', [
  readyMessageSchema,
  handshakeMessageSchema,
  handshakeAckMessageSchema,
  handshakeNackMessageSchema,
  rpcMessageSchema,
  rpcResponseMessageSchema,
  eventMessageSchema,
  closeMessageSchema,
]);

export type TransportMessage = z.infer<typeof transportMessageSchema>;
export type HandshakeMessage = z.infer<typeof handshakeMessageSchema>;
export type HandshakeNackMessage = z.infer<typeof handshakeNackMessageSchema>;
export type HandshakeNackReason = HandshakeNackMessage['payload']['reason'];
export type RpcMessage = z.infer<typeof rpcMessageSchema>;

/** Parses unknown postMessage data; null for anything that is not a valid Giano message. */
export function parseTransportMessage(data: unknown): TransportMessage | null {
  const result = transportMessageSchema.safeParse(data);
  return result.success ? result.data : null;
}

/** EIP-1193 provider error codes used over the wire. */
export const RPC_ERRORS = {
  USER_REJECTED: 4001,
  UNAUTHORIZED: 4100,
  UNSUPPORTED_METHOD: 4200,
  DISCONNECTED: 4900,
  /** The chain is served but temporarily unreachable — retryable, unlike UNSUPPORTED_CHAIN. */
  CHAIN_DISCONNECTED: 4901,
  /** EIP-3326's "Unrecognized chain ID" — this deployment does not serve that chain (permanent). */
  UNSUPPORTED_CHAIN: 4902,
  INTERNAL: -32603,
} as const;
