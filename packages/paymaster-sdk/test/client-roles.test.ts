import type { Hex } from "viem";
import { describe, expect, it } from "vitest";
import {
	GianoPaymasterClient,
	type PaymasterPublicClient,
	type PaymasterWalletClient,
} from "../src/client";
import { DEFAULT_ADMIN_ROLE, PAYMASTER_ROLES } from "../src/roles";

const PROXY = "0x4Bf0c2F63C4fA20D88B8126298fFFC64710Ece96" as const;
const HOLDER = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed" as const;

function recording() {
	const simulated: { functionName: string; args: readonly unknown[] }[] = [];
	const publicClient = {
		simulateContract: async (request: {
			functionName: string;
			args: readonly unknown[];
		}) => {
			simulated.push({
				functionName: request.functionName,
				args: request.args,
			});
			return { request };
		},
	} as unknown as PaymasterPublicClient;
	const walletClient = {
		account: { address: HOLDER, type: "json-rpc" },
		writeContract: async () => `0x${"ab".repeat(32)}` as Hex,
	} as unknown as PaymasterWalletClient;
	return {
		simulated,
		client: new GianoPaymasterClient({
			address: PROXY,
			publicClient,
			walletClient,
		}),
	};
}

describe("role writes", () => {
	it("revokes a named role, or DEFAULT_ADMIN_ROLE by its zero hash", async () => {
		const { client, simulated } = recording();
		await client.revokeRole("PAUSER_ROLE", HOLDER);
		await client.revokeRole("DEFAULT_ADMIN_ROLE", HOLDER);
		expect(simulated).toEqual([
			{
				functionName: "revokeRole",
				args: [PAYMASTER_ROLES.PAUSER_ROLE, HOLDER],
			},
			{ functionName: "revokeRole", args: [DEFAULT_ADMIN_ROLE, HOLDER] },
		]);
	});

	it("renounces with the caller's own address as the confirmation", async () => {
		const { client, simulated } = recording();
		await client.renounceRole("ROLE_ADMIN", HOLDER);
		expect(simulated).toEqual([
			{
				functionName: "renounceRole",
				args: [PAYMASTER_ROLES.ROLE_ADMIN, HOLDER],
			},
		]);
	});
});
