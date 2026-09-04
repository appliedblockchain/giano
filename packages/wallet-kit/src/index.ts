/**
 * @appliedblockchain/giano-wallet-kit — the framework-agnostic orchestration a Giano
 * wallet origin is built from (WALLET-SDK-REQUIREMENTS.md / WALLET-SDK-SPECS.md).
 *
 * The kit is headless: it owns config validation, the per-chain runtimes, the transport
 * host with its consent gate, and the wallet-management controller — and no pixel. It is
 * built on the published primitives (`giano-wallet-core`, `giano-wallet-transport`) and
 * the documented wallet-api exactly as a tenant could build directly (D3, D5), and it
 * re-exports only what a wallet UI needs (WK-24).
 */

// ── configuration (WK-06, WK-07) ──
export {
  loadWalletConfig,
  resolveWalletConfig,
  type LoadWalletConfigOptions,
  type RawWalletConfig,
  type ResolveWalletConfigOptions,
  type WalletChainConfig,
  type WalletConfig,
} from './config';

// ── runtimes (WK-01…WK-05) ──
export { createWalletRuntimes, type SponsorshipPreflight, type TransactionRequest, type WalletRuntime, type WalletRuntimes } from './runtimes';

// ── the host and consent (WK-08…WK-12) ──
export { createWalletHost, type CreateWalletHostOptions, type WalletHost } from './host';
export { toRpcError, type PendingRequest, type RequestStore } from './requests';

// ── the wallet-management controller (WK-16…WK-21) ──
export {
  createManagementController,
  type AddressInputError,
  type CreateManagementControllerOptions,
  type ManagementChainStatus,
  type ManagementController,
  type ManagementFlow,
  type ManagementState,
  type OwnerRow,
  type SponsorshipRefusal,
} from './management/controller';
export type { ChainProgress, ChainStepState } from './management/apply-owner-change';

// ── the error shapes and reason codes a client keys behaviour off (spec §9, WK-15) ──
export { WalletManagementApiError, type SponsorshipRefusalReason, type SponsorshipRuleResult } from '@appliedblockchain/giano-wallet-core';
export { TransportRpcError } from '@appliedblockchain/giano-wallet-transport';
