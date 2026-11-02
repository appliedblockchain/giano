import type { Hex } from "viem";
import { useConsole } from "../shell/ConsoleContext";
import { ActionButton } from "./actions";

/**
 * Executes a ready timelock operation from the connected wallet (openspec G8): allowed where the
 * timelock's executors are open or the wallet holds EXECUTOR_ROLE, and only for an operation whose
 * scheduling was in the blocks read, since that is what its calls are rebuilt from.
 */
export function ExecuteButton({
	operationId,
	mayExecute,
	size = "xs",
}: {
	operationId: Hex;
	mayExecute: boolean;
	size?: "xs" | "sm";
}) {
	const { timelock, timelockOperations } = useConsole();
	const operation = timelockOperations.operations.find(
		(entry) => entry.id === operationId,
	);
	if (!timelock || !operation || operation.state !== "ready") return null;
	const summary = operation.calls
		.map((call) => call.decoded?.summary ?? `a call to ${call.target}`)
		.join("; ");
	return (
		<ActionButton
			target={{
				gate: operation.complete
					? {
							allowed: mayExecute,
							reason:
								"Needs the timelock's EXECUTOR_ROLE; its executors are not open.",
						}
					: {
							allowed: false,
							reason:
								"Scheduled before the blocks read, so its calls cannot be rebuilt here. Look further back in the Timelock tab.",
						},
			}}
			label="Execute"
			size={size}
			send={() => timelock.executeOperation(operation)}
			confirm={{
				title: "Execute the timelock operation",
				effect: `${summary[0]?.toUpperCase()}${summary.slice(1)}. It takes effect in this transaction and cannot be cancelled after.`,
				confirmLabel: "Execute",
			}}
		/>
	);
}
