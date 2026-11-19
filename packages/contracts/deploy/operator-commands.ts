/**
 * The deploy:cli commands that the operator launcher (deploy/operations.ts) runs, built from the
 * selected chain profile. Kept apart from the launcher, which runs on import, so tests can check them.
 */
import { TIMELOCKED_FUNCTION_NAMES, type TimelockDelays } from "../timelock";
import type { ProfileFile } from "./profiles";

/** The launcher commands that send transactions, and so take --signed-rpc. */
export const SIGNED_RPC_COMMANDS = ["provision", "timelock", "handoff"];

/**
 * The deploy:cli arguments `contracts:timelock` and `contracts:handoff` run, for `selected`. With
 * `signedRpc`, deploy:cli signs every request with ROLE_ADMIN_PRIVATE_KEY.
 */
export function timelockCommand(
	command: "timelock" | "handoff",
	selected: ProfileFile,
	rpc: string,
	signedRpc: boolean,
): string[] {
	const { profile } = selected;
	const timelock = profile.timelock;
	if (!timelock) throw new Error(`${selected.file} has no timelock section`);
	const delays = timelock.delays as TimelockDelays;
	const args =
		command === "timelock"
			? [
					"timelock",
					"--rpc",
					rpc,
					// The selected profile, so the child resolves the same class, overrides and proxy.
					"--chain-config",
					selected.file,
					"--release",
					profile.release,
					...timelock.proposers.flatMap((p) => ["--proposer", p]),
					...timelock.executors.flatMap((e) => ["--executor", e]),
					"--min-delay",
					String(delays.minDelay),
					...TIMELOCKED_FUNCTION_NAMES.flatMap((name) => [
						"--delay",
						`${name}=${delays[name]}`,
					]),
				]
			: [
					"handoff",
					"--rpc",
					rpc,
					"--chain-config",
					selected.file,
					"--timelock",
					timelock.address as string,
					"--execute",
				];
	return signedRpc ? [...args, "--signed-rpc"] : args;
}
