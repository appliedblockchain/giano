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

export type {
	DescribedTransaction,
	DescriptionField,
	DescriptionSource,
	DescriptionWarning,
	DescriptionWarningCode,
	TransactionDescription,
	UnknownReason,
	UnknownTransaction,
} from "@appliedblockchain/giano-tx-describe";
// ── the error shapes and reason codes a client keys behaviour off (spec §9, WK-15) ──
export {
	type SponsorshipRefusalReason,
	type SponsorshipRuleResult,
	WalletManagementApiError,
} from "@appliedblockchain/giano-wallet-core";
export { TransportRpcError } from "@appliedblockchain/giano-wallet-transport";
// ── configuration (WK-06, WK-07) ──
export {
	type LoadWalletConfigOptions,
	loadWalletConfig,
	type RawWalletConfig,
	type ResolveWalletConfigOptions,
	resolveWalletConfig,
	type WalletChainConfig,
	type WalletConfig,
} from "./config";
// ── transaction descriptions (the review screen's account of a request) ──
export {
	type CreateTransactionDescriberOptions,
	createTransactionDescriber,
} from "./describe";
// ── the host and consent (WK-08…WK-12) ──
export {
	type CreateWalletHostOptions,
	createWalletHost,
	type WalletHost,
} from "./host";
export type {
	ChainProgress,
	ChainStepState,
} from "./management/apply-owner-change";
// ── the wallet-management controller (WK-16…WK-21) ──
export {
	type AddressInputError,
	type CreateManagementControllerOptions,
	createManagementController,
	type ManagementChainStatus,
	type ManagementController,
	type ManagementFlow,
	type ManagementState,
	type OwnerRow,
	type SponsorshipRefusal,
} from "./management/controller";
export { type PendingRequest, type RequestStore, toRpcError } from "./requests";
// ── runtimes (WK-01…WK-05) ──
export {
	createWalletRuntimes,
	type SponsorshipPreflight,
	type TransactionRequest,
	type WalletRuntime,
	type WalletRuntimes,
} from "./runtimes";
