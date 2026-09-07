// Thin Giano SDK: connect a dApp to a deployed Giano wallet origin. No WebAuthn,
// credential storage or bundler code is reachable from this entry point — all wallet
// trust lives in the wallet origin (popup) and the wallet-api it fronts.
export {
  createGianoWalletProvider,
  type CreateGianoWalletProviderParams,
  type GianoWalletProvider,
} from './thin/create-giano-wallet-provider';
export { createGianoConnector, UnsupportedChainSwitchError, type CreateGianoConnectorParams, type GianoProviderLike, type SendTransactionFnParams } from './connector';
export { giano } from './gianoWallet';
export {
  HandshakeRefusedError,
  RPC_ERRORS,
  TransportError,
  TransportRpcError,
  UnsupportedChainError,
} from '@appliedblockchain/giano-wallet-transport';
