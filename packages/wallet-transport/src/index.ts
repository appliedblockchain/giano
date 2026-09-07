export { TransportClient, type TransportClientOptions } from './client';
export {
  HandshakeRefusedError,
  TransportError,
  TransportRpcError,
  UnsupportedChainError,
  type TransportErrorCode,
} from './errors';
export { TransportHost, type RequestContext, type RequestHandler, type TransportHostOptions } from './host';
export { PopupManager, type PopupManagerOptions } from './popup-manager';
export {
  PROTOCOL_VERSION,
  RPC_ERRORS,
  parseTransportMessage,
  transportMessageSchema,
  type HandshakeNackMessage,
  type HandshakeNackReason,
  type RpcError,
  type TransportMessage,
} from './protocol';
