import type {
	GianoTimelockClient,
	PaymasterRoleName,
	SafeTransactionBatch,
	TimelockedFunctionName,
	TimelockProposalDraft,
} from "@appliedblockchain/giano-paymaster-sdk";
import type { Address, Hex } from "viem";

/**
 * A timelocked change an operator wants made (G9), before it is a proposal.
 *
 * The console never sends these on a handed-off deployment: the role is the timelock's, and the
 * timelock's proposer is a Safe (R3). It builds the proposal — with the delay read from the
 * timelock — and hands the operator the calldata and the Safe Transaction Builder file instead.
 */
export type ProposalRequest =
	| { kind: "setDefaultFee"; feeWei: bigint }
	| {
			kind: "setTenantFee";
			tenantId: Hex;
			hasOverride: boolean;
			feeWei: bigint;
	  }
	| {
			kind: "setTenantWithdrawAddress";
			tenantId: Hex;
			withdrawAddress: Address;
	  }
	| {
			kind: "grantRole" | "revokeRole";
			role: PaymasterRoleName;
			account: Address;
	  };

/** Opens the proposal flow. Undefined where the deployment has no timelock configured. */
export type Propose = (request: ProposalRequest) => void;

/** The paymaster function a request calls, for its delay and the role that gates it. */
export function requestFunction(
	request: ProposalRequest,
): TimelockedFunctionName {
	return request.kind;
}

export function buildProposal(
	timelock: GianoTimelockClient,
	request: ProposalRequest,
): Promise<TimelockProposalDraft> {
	switch (request.kind) {
		case "setDefaultFee":
			return timelock.proposeSetDefaultFee(request.feeWei);
		case "setTenantFee":
			return timelock.proposeSetTenantFee(
				request.tenantId,
				request.hasOverride,
				request.feeWei,
			);
		case "setTenantWithdrawAddress":
			return timelock.proposeSetTenantWithdrawAddress(
				request.tenantId,
				request.withdrawAddress,
			);
		case "grantRole":
			return timelock.proposeGrantRole(request.role, request.account);
		case "revokeRole":
			return timelock.proposeRevokeRole(request.role, request.account);
	}
}

/**
 * Saves a Safe Transaction Builder batch as a file, named for its step and operation id so two
 * downloads in one sitting cannot be confused for each other. Returns the file name.
 */
export function downloadSafeBatch(
	batch: SafeTransactionBatch,
	step: "schedule" | "execute" | "cancel",
	id: Hex,
): string {
	const name = `giano-timelock-${step}-${id.slice(2, 10)}.json`;
	const url = URL.createObjectURL(
		new Blob([`${JSON.stringify(batch, null, 2)}\n`], {
			type: "application/json",
		}),
	);
	const link = document.createElement("a");
	link.href = url;
	link.download = name;
	document.body.appendChild(link);
	link.click();
	document.body.removeChild(link);
	URL.revokeObjectURL(url);
	return name;
}

/** `in 2h 5m` / `3m ago`, for an ETA next to its absolute time. */
export function relativeTime(unixSeconds: number, now = Date.now()): string {
	const seconds = Math.round(unixSeconds - now / 1000);
	const magnitude = Math.abs(seconds);
	const parts: string[] = [];
	const days = Math.floor(magnitude / 86400);
	const hours = Math.floor((magnitude % 86400) / 3600);
	const minutes = Math.floor((magnitude % 3600) / 60);
	if (days) parts.push(`${days}d`);
	if (hours) parts.push(`${hours}h`);
	if (minutes && !days) parts.push(`${minutes}m`);
	if (parts.length === 0) parts.push(`${magnitude}s`);
	return seconds >= 0 ? `in ${parts.join(" ")}` : `${parts.join(" ")} ago`;
}
