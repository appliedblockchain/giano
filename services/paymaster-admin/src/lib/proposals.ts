import {
	type GianoTimelockClient,
	PAYMASTER_ROLES,
	type PaymasterRoleName,
	type ProposeOptions,
	type SafeTransactionBatch,
	TIMELOCK_ROLES,
	type TimelockCall,
	type TimelockedFunctionName,
	type TimelockProposalDraft,
	type TimelockRoleName,
	toTenantId,
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
	| { kind: "upgradeToAndCall"; implementation: Address; data: Hex }
	| {
			kind: "grantRole" | "revokeRole";
			role: PaymasterRoleName;
			account: Address;
	  }
	/** Grant to `to` and revoke from `from` in one operation, so the role is never held by neither. */
	| {
			kind: "rotateRole";
			role: PaymasterRoleName;
			from: Address;
			to: Address;
	  }
	/** The timelock's own floor. */
	| { kind: "updateDelay"; seconds: bigint }
	/** One timelocked paymaster function's own delay; 0 falls back to the floor. */
	| {
			kind: "setFunctionDelay";
			functionName: TimelockedFunctionName;
			/** The function's selector on the paymaster, as the timelock's config reports it. */
			selector: Hex;
			seconds: bigint;
	  }
	/** The timelock's own proposers, cancellers and executors. */
	| {
			kind: "grantTimelockRole" | "revokeTimelockRole";
			role: TimelockRoleName;
			account: Address;
	  };

/** Opens the proposal flow. Undefined where the deployment has no timelock configured. */
export type Propose = (request: ProposalRequest) => void;

/**
 * The paymaster function a request calls, for the role that gates it and why it waits. Undefined
 * for a change to the timelock itself, which no paymaster role gates: only the timelock can make it.
 */
export function requestFunction(
	request: ProposalRequest,
): TimelockedFunctionName | undefined {
	switch (request.kind) {
		case "rotateRole":
			return "grantRole";
		case "updateDelay":
		case "setFunctionDelay":
		case "grantTimelockRole":
		case "revokeTimelockRole":
			return undefined;
		default:
			return request.kind;
	}
}

/** The calls a request makes, on the paymaster or on the timelock itself. */
export function requestCalls(
	timelock: GianoTimelockClient,
	request: ProposalRequest,
): TimelockCall[] {
	const paymaster = (name: string, args: readonly unknown[]) =>
		timelock.paymasterCall(name, args);
	const self = (name: string, args: readonly unknown[]) =>
		timelock.timelockCall(name, args);
	switch (request.kind) {
		case "setDefaultFee":
			return [paymaster("setDefaultFee", [request.feeWei])];
		case "setTenantFee":
			return [
				paymaster("setTenantFee", [
					toTenantId(request.tenantId),
					request.hasOverride,
					request.feeWei,
				]),
			];
		case "setTenantWithdrawAddress":
			return [
				paymaster("setTenantWithdrawAddress", [
					toTenantId(request.tenantId),
					request.withdrawAddress,
				]),
			];
		case "upgradeToAndCall":
			return [
				paymaster("upgradeToAndCall", [request.implementation, request.data]),
			];
		case "grantRole":
		case "revokeRole":
			return [
				paymaster(request.kind, [
					PAYMASTER_ROLES[request.role],
					request.account,
				]),
			];
		case "rotateRole":
			// Grant first: executed together, the role is never held by nobody.
			return [
				paymaster("grantRole", [PAYMASTER_ROLES[request.role], request.to]),
				paymaster("revokeRole", [PAYMASTER_ROLES[request.role], request.from]),
			];
		case "updateDelay":
			return [self("updateDelay", [request.seconds])];
		case "setFunctionDelay":
			return [
				self("setFunctionDelay", [
					timelock.paymaster,
					request.selector,
					request.seconds,
				]),
			];
		case "grantTimelockRole":
			return [
				self("grantRole", [TIMELOCK_ROLES[request.role], request.account]),
			];
		case "revokeTimelockRole":
			return [
				self("revokeRole", [TIMELOCK_ROLES[request.role], request.account]),
			];
	}
}

/** One proposal from one or more requests, in order: a batch executes all of them or none. */
export function buildProposal(
	timelock: GianoTimelockClient,
	requests: readonly ProposalRequest[],
	options?: ProposeOptions,
): Promise<TimelockProposalDraft> {
	return timelock.propose(
		requests.flatMap((request) => requestCalls(timelock, request)),
		options,
	);
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
