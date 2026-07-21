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

/** dApp → wallet: start a session; carries SDK version + requested capabilities. */
export const handshakeMessageSchema = z.object({
  ...base,
  type: z.literal('handshake'),
  payload: z.object({
    sdkVersion: z.string(),
    capabilities: z.array(z.string()).default([]),
  }),
});

/** wallet → dApp: session accepted; carries wallet version + granted capabilities. */
export const handshakeAckMessageSchema = z.object({
  ...base,
  type: z.literal('handshake:ack'),
  payload: z.object({
    walletVersion: z.string(),
    capabilities: z.array(z.string()).default([]),
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
  rpcMessageSchema,
  rpcResponseMessageSchema,
  eventMessageSchema,
  closeMessageSchema,
]);

export type TransportMessage = z.infer<typeof transportMessageSchema>;
export type HandshakeMessage = z.infer<typeof handshakeMessageSchema>;
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
  CHAIN_DISCONNECTED: 4901,
  INTERNAL: -32603,
} as const;
