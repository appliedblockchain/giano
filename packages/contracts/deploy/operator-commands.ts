/**
 * The deploy:cli commands that the operator launcher (deploy/operations.ts) runs, built from the
 * selected chain profile. Kept apart from the launcher, which runs on import, so tests can check them.
 */
import { getAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { TIMELOCKED_FUNCTION_NAMES, type TimelockDelays } from "../timelock";
import type { ProfileFile } from "./profiles";

/** The launcher commands that send transactions, and so take --signed-rpc. */
export const SIGNED_RPC_COMMANDS = ["provision", "timelock", "handoff"];

/**
 * What the operator environment lacks for `contracts:provision` or `contracts:sponsorship`, all of
 * it at once, so one run (or one --plan) names every missing setting. Empty when nothing is missing.
 * `roleAdmin` is PAYMASTER_ROLE_ADMIN or the profile's roleAdmin. No message quotes a key.
 */
export function operatorInputProblems(
	command: "provision" | "sponsorship",
	env: NodeJS.ProcessEnv,
	roleAdmin: string | null | undefined,
): string[] {
	const problems: string[] = [];
	let admin: string | undefined;
	if (!roleAdmin)
		problems.push(
			"Persist ROLE_ADMIN in the chain profile or provide PAYMASTER_ROLE_ADMIN.",
		);
	else
		try {
			admin = getAddress(roleAdmin);
		} catch {
			problems.push(`ROLE_ADMIN ${roleAdmin} is not an address.`);
		}
	if (command === "provision") {
		let operator: string | undefined;
		try {
			// Untrimmed: the workflow uses the key exactly as written, so a stray space fails here.
			operator = privateKeyToAccount(
				env.DEPLOYER_PRIVATE_KEY as `0x${string}`,
			).address;
		} catch {
			problems.push(
				"Provide the ROLE_ADMIN operator key as DEPLOYER_PRIVATE_KEY. This provisioning workflow requires an EOA admin.",
			);
		}
		if (operator && admin && operator !== admin)
			problems.push(
				`DEPLOYER_PRIVATE_KEY is the key of ${operator}, not of ROLE_ADMIN ${admin} (the profile's roleAdmin, or PAYMASTER_ROLE_ADMIN).`,
			);
		// The sponsorship signer by address: a production signer's key never leaves its HSM.
		if (
			!env.SPONSORSHIP_SIGNER_ADDRESS?.trim() &&
			!env.SPONSORSHIP_SIGNER_KEY?.trim()
		)
			problems.push(
				"Provide SPONSORSHIP_SIGNER_ADDRESS (the address wallet-api signs sponsorships with).",
			);
	}
	const needed =
		command === "provision"
			? ["PAYMASTER_TENANTS"]
			: ["ADMIN_API_KEY", "TENANT_SLUG", "WALLET_API_URL"];
	for (const name of needed)
		if (!env[name]?.trim()) problems.push(`Provide ${name}.`);
	return problems;
}

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
