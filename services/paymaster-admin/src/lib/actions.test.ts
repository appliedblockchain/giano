import { describe, expect, it } from "vitest";
import { resolveAction } from "./actions";

const none = { myRoles: [], connected: true, hasTimelock: false };

describe("resolveAction", () => {
	it("sends when the wallet holds the role, timelocked or not", () => {
		expect(
			resolveAction(
				{ role: "PAUSER_ROLE" },
				{ ...none, myRoles: ["PAUSER_ROLE"] },
			),
		).toEqual({ kind: "send" });
		// A devnet key holding a timelocked role sends it directly, timelock or no timelock.
		expect(
			resolveAction(
				{ operation: "setTenantFee" },
				{ ...none, myRoles: ["FEE_ADMIN_ROLE"], hasTimelock: true },
			),
		).toEqual({ kind: "send" });
	});

	it("proposes a timelocked operation the wallet cannot send, when there is a timelock", () => {
		expect(
			resolveAction(
				{ operation: "setTenantFee" },
				{ ...none, hasTimelock: true },
			),
		).toEqual({ kind: "propose" });
		// Building a proposal sends nothing, so it needs no wallet.
		expect(
			resolveAction(
				{ operation: "upgradeToAndCall" },
				{ ...none, connected: false, hasTimelock: true },
			),
		).toEqual({ kind: "propose" });
	});

	it("names the role, and the missing timelock, when it can do neither", () => {
		expect(resolveAction({ operation: "upgradeToAndCall" }, none)).toEqual({
			kind: "blocked",
			reason:
				"Needs UPGRADER_ROLE, and this deployment has no timelock configured to propose to.",
			needsWallet: false,
		});
		expect(
			resolveAction({ role: "PAUSER_ROLE" }, { ...none, hasTimelock: true }),
		).toEqual({
			kind: "blocked",
			reason: "Needs PAUSER_ROLE.",
			needsWallet: false,
		});
	});

	it("asks for a wallet first when none is connected", () => {
		expect(
			resolveAction({ role: "PAUSER_ROLE" }, { ...none, connected: false }),
		).toEqual({
			kind: "blocked",
			reason: "Connect a wallet to send this.",
			needsWallet: true,
		});
	});

	it("never sends from roles a disconnected wallet was last seen with", () => {
		expect(
			resolveAction(
				{ role: "PAUSER_ROLE" },
				{ myRoles: ["PAUSER_ROLE"], connected: false, hasTimelock: false },
			).kind,
		).toBe("blocked");
	});

	it("lets anyone with a wallet send an open write", () => {
		expect(resolveAction({ anyone: true }, none)).toEqual({ kind: "send" });
		expect(
			resolveAction({ anyone: true }, { ...none, connected: false }).kind,
		).toBe("blocked");
	});

	it("sends a gated write when the caller says it may, and gives the caller's reason when not", () => {
		const gate = (allowed: boolean) => ({
			gate: { allowed, reason: "Needs the timelock's EXECUTOR_ROLE." },
		});
		expect(resolveAction(gate(true), none)).toEqual({ kind: "send" });
		expect(resolveAction(gate(false), none)).toEqual({
			kind: "blocked",
			reason: "Needs the timelock's EXECUTOR_ROLE.",
			needsWallet: false,
		});
		expect(resolveAction(gate(true), { ...none, connected: false }).kind).toBe(
			"blocked",
		);
	});
});
