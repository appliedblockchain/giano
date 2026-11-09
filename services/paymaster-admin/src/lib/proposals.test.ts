import {
	type GianoTimelockClient,
	PAYMASTER_ROLES,
} from "@appliedblockchain/giano-paymaster-sdk";
import { describe, expect, it } from "vitest";
import { buildProposal, requestFunction } from "./proposals";

const FROM = "0x1111111111111111111111111111111111111111";
const TO = "0x2222222222222222222222222222222222222222";

describe("buildProposal for a rotation", () => {
	it("proposes one operation: the grant to the new holder, then the revoke from the old one", async () => {
		const proposed: unknown[] = [];
		const timelock = {
			paymasterCall: (functionName: string, args: readonly unknown[]) => ({
				functionName,
				args,
			}),
			propose: async (calls: unknown[], options?: unknown) => {
				proposed.push(calls);
				return { calls, options };
			},
		} as unknown as GianoTimelockClient;

		await buildProposal(timelock, [
			{ kind: "rotateRole", role: "PAUSER_ROLE", from: FROM, to: TO },
		]);

		expect(proposed).toEqual([
			[
				{ functionName: "grantRole", args: [PAYMASTER_ROLES.PAUSER_ROLE, TO] },
				{
					functionName: "revokeRole",
					args: [PAYMASTER_ROLES.PAUSER_ROLE, FROM],
				},
			],
		]);
	});

	it("waits the grant's delay, since the operation is gated as grantRole", () => {
		expect(
			requestFunction({
				kind: "rotateRole",
				role: "PAUSER_ROLE",
				from: FROM,
				to: TO,
			}),
		).toBe("grantRole");
	});
});
