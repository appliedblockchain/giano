import { encodeAddOwnerPublicKey } from "@appliedblockchain/giano-wallet-core";
import { pad } from "viem";
import type { SponsorshipPreflight, WalletRuntime } from "../runtimes";
import { ensureAccount } from "./apply-owner-change";

/**
 * Asks the rules engine whether a wallet-management operation would be sponsored, BEFORE
 * any ceremony is started (WM-68, WK-13): a user must never be walked through a passkey
 * prompt for an operation that was already refused. The calldata is a representative
 * addOwnerPublicKey self-call, with no value.
 *
 * One representative call answers for every operation this view sends, because the rules
 * engine sponsors the same three owner functions in the same way: addOwnerPublicKey,
 * addOwnerAddress and removeOwnerAtIndex, each with no value (OWNER_MANAGEMENT_SELECTORS
 * in wallet-api's sponsorship-rules.ts). Any other self-call is refused. A new management
 * operation must be added to that list before this view sends it. Otherwise this
 * preflight reports it as sponsored, and the rules engine refuses it after the passkey
 * prompt, which WM-68 forbids.
 */
export async function preflightManagement({
	runtime,
	walletAddress,
}: {
	runtime: WalletRuntime;
	walletAddress: `0x${string}`;
}): Promise<SponsorshipPreflight> {
	if (!(await ensureAccount(runtime))) {
		return { state: "unavailable", message: "the wallet is not connected yet" };
	}
	const zero = pad("0x00", { size: 32 });
	return runtime.checkSponsorship({
		to: walletAddress,
		data: encodeAddOwnerPublicKey(zero, zero),
	});
}
