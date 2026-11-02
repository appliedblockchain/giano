import {
	type PaymasterRoleName,
	TIMELOCKED_OPERATIONS,
	type TimelockedFunctionName,
} from "@appliedblockchain/giano-paymaster-sdk";

/**
 * What a write control does for the wallet in front of it (openspec D6).
 *
 * - `send`: the wallet holds the role, so it signs the call itself. A timelocked role a wallet
 *   holds — one key holding everything on a devnet — is sent directly too.
 * - `propose`: the call is timelocked, the wallet lacks the role, and the deployment has a timelock
 *   to propose to. Nothing is signed here; the proposal dialog builds the call for the proposer.
 * - `blocked`: neither. `reason` says why, in words the control shows beside itself; `needsWallet`
 *   when connecting one is the first thing missing.
 */
export type ActionPlan =
	| { kind: "send" }
	| { kind: "propose" }
	| { kind: "blocked"; reason: string; needsWallet: boolean };

/**
 * A write is named by the timelocked function it calls, by the role an immediate one needs, or as
 * open to anyone with a wallet (funding a tenant).
 */
export type ActionTarget =
	| { operation: TimelockedFunctionName }
	| { role: PaymasterRoleName }
	| { anyone: true };

export type ActionContext = {
	/** Paymaster roles the connected wallet holds; empty when none is connected. */
	myRoles: readonly PaymasterRoleName[];
	connected: boolean;
	/** Whether the deployment names a `timelockAddress` to propose to. */
	hasTimelock: boolean;
};

export function targetRole(
	target: ActionTarget,
): PaymasterRoleName | undefined {
	if ("anyone" in target) return undefined;
	return "operation" in target
		? (TIMELOCKED_OPERATIONS[target.operation].role as PaymasterRoleName)
		: target.role;
}

export function resolveAction(
	target: ActionTarget,
	{ myRoles, connected, hasTimelock }: ActionContext,
): ActionPlan {
	const role = targetRole(target);
	const timelocked = "operation" in target;

	if (connected && (role === undefined || myRoles.includes(role)))
		return { kind: "send" };
	// A proposal is built, not sent, so it needs no wallet: anyone reading the console may draft one
	// for the proposer.
	if (timelocked && hasTimelock) return { kind: "propose" };
	if (!connected)
		return {
			kind: "blocked",
			reason: "Connect a wallet to send this.",
			needsWallet: true,
		};
	if (timelocked)
		return {
			kind: "blocked",
			reason: `Needs ${role}, and this deployment has no timelock configured to propose to.`,
			needsWallet: false,
		};
	return { kind: "blocked", reason: `Needs ${role}.`, needsWallet: false };
}
