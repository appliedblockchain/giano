import type { WriteResult } from "@appliedblockchain/giano-paymaster-sdk";
import {
	Button,
	type ButtonProps,
	Dialog,
	Portal,
	Stack,
	Text,
} from "@chakra-ui/react";
import { type ReactNode, useEffect, useState } from "react";
import { LuClock } from "react-icons/lu";
import { useWrite } from "../hooks/useWrite";
import {
	type ActionPlan,
	type ActionTarget,
	resolveAction,
} from "../lib/actions";
import type { ProposalRequest } from "../lib/proposals";
import { useConsole } from "../shell/ConsoleContext";

/**
 * Resolves a write for the wallet in front of it: send, propose, or blocked with the reason
 * (openspec D6). Every write control goes through this, so none decides on its own which role it
 * needs or whether the timelock applies.
 */
export function useChainAction(target: ActionTarget): ActionPlan {
	const { myRoles, wallet, timelock } = useConsole();
	return resolveAction(target, {
		myRoles,
		connected: wallet !== undefined,
		hasTimelock: timelock !== undefined,
	});
}

export type Confirmation = {
	title: string;
	/** What happens, stated so the operator can stop: "Bundlers stop accepting the paymaster…". */
	effect: ReactNode;
	confirmLabel?: string;
};

type ActionButtonProps = {
	target: ActionTarget;
	/** The verb, as the Send control reads: "Pause", "Set fee". Propose reads "Propose set fee". */
	label: string;
	/** The write. Undefined while the form's inputs are not valid, which disables the control. */
	send?: () => Promise<WriteResult>;
	/** For a timelocked operation: the call to propose. Undefined while the inputs are not valid. */
	proposal?: ProposalRequest;
	/** Set for a destructive write: asked before the wallet is (openspec C4). */
	confirm?: Confirmation;
	/** Called once the write is mined, e.g. to clear the form. */
	onDone?: () => void;
	icon?: ReactNode;
	destructive?: boolean;
	/**
	 * A quiet control: a ghost button, for an action that sits beside a louder one and must not be
	 * mistaken for it — renouncing your own role next to revoking someone's. A destructive one still
	 * asks first, in red.
	 */
	quiet?: boolean;
	size?: ButtonProps["size"];
	/** Set while something else on the form makes the write impossible. */
	disabled?: boolean;
};

/**
 * One write control in its three states (openspec D6): Send in the brand colour, Propose in the
 * timelock's purple with a clock, and blocked — shown, disabled, and saying which role it needs or
 * that a wallet must be connected. Never hidden for a missing role: an operator who cannot act still
 * learns the control exists and what would let them use it.
 */
export function ActionButton({
	target,
	label,
	send,
	proposal,
	confirm,
	onDone,
	icon,
	destructive,
	quiet,
	size = "sm",
	disabled,
}: ActionButtonProps) {
	const plan = useChainAction(target);
	const { propose, refresh } = useConsole();
	const { run, busy } = useWrite(refresh);
	const [confirming, setConfirming] = useState(false);
	const timelocked = "operation" in target;

	// A refresh can block the write, turn it into a proposal (the wallet's role changed), or drop its
	// confirmation while the dialog is open: it closes rather than sending, and does not reopen by
	// itself when the state flips back.
	const sendable = plan.kind === "send";
	const asks = confirm !== undefined;
	useEffect(() => {
		if (!sendable || !asks) setConfirming(false);
	}, [sendable, asks]);

	const doSend = async () => {
		if (!send || !sendable) return;
		setConfirming(false);
		if (await run(label, send)) onDone?.();
	};

	// A timelocked write the wallet holds no role for is a proposal, even when it cannot be proposed
	// here: the control says Propose, disabled, and why.
	if (
		plan.kind === "propose" ||
		(plan.kind === "blocked" && timelocked && !plan.needsWallet)
	) {
		const text = `Propose ${label.charAt(0).toLowerCase()}${label.slice(1)}`;
		return (
			<Stack gap="1" align="flex-start">
				<Button
					size={size}
					colorPalette="timelock"
					variant="outline"
					disabled={
						plan.kind === "blocked" || !proposal || !propose || disabled
					}
					onClick={() => proposal && propose?.(proposal)}
				>
					<LuClock aria-hidden="true" /> {text}
				</Button>
				{plan.kind === "blocked" && <Reason>{plan.reason}</Reason>}
			</Stack>
		);
	}

	return (
		<Stack gap="1" align="flex-start">
			<Button
				size={size}
				colorPalette={quiet ? "gray" : destructive ? "red" : "brand"}
				variant={quiet ? "ghost" : destructive ? "outline" : "solid"}
				disabled={plan.kind === "blocked" || !send || busy || disabled}
				loading={busy}
				onClick={() => (confirm ? setConfirming(true) : void doSend())}
			>
				{icon}
				{label}
			</Button>
			{plan.kind === "blocked" && <Reason>{plan.reason}</Reason>}
			{confirm && (
				<ConfirmDialog
					open={confirming}
					confirmation={confirm}
					destructive={destructive}
					onConfirm={() => void doSend()}
					onCancel={() => setConfirming(false)}
				/>
			)}
		</Stack>
	);
}

function Reason({ children }: { children: ReactNode }) {
	return (
		<Text fontSize="xs" color="fg.muted">
			{children}
		</Text>
	);
}

/** Names the effect of a write and sends nothing until it is confirmed. */
export function ConfirmDialog({
	open,
	confirmation,
	destructive,
	onConfirm,
	onCancel,
}: {
	open: boolean;
	confirmation: Confirmation;
	destructive?: boolean;
	onConfirm: () => void;
	onCancel: () => void;
}) {
	return (
		<Dialog.Root
			open={open}
			onOpenChange={(event) => !event.open && onCancel()}
			role="alertdialog"
		>
			<Portal>
				<Dialog.Backdrop />
				<Dialog.Positioner>
					<Dialog.Content>
						<Dialog.Header>
							<Dialog.Title>{confirmation.title}</Dialog.Title>
						</Dialog.Header>
						<Dialog.Body>
							<Text fontSize="sm">{confirmation.effect}</Text>
						</Dialog.Body>
						<Dialog.Footer>
							<Button variant="ghost" onClick={onCancel}>
								Cancel
							</Button>
							<Button
								colorPalette={destructive ? "red" : "brand"}
								onClick={onConfirm}
							>
								{confirmation.confirmLabel ?? confirmation.title}
							</Button>
						</Dialog.Footer>
					</Dialog.Content>
				</Dialog.Positioner>
			</Portal>
		</Dialog.Root>
	);
}
