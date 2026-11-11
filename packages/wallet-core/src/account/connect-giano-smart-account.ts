import { gianoSmartWalletAbi } from "@appliedblockchain/giano-contracts";
import { type Address, isAddressEqual } from "viem";
import type { WebAuthnAccount } from "viem/account-abstraction";
import { readContract } from "viem/actions";
import { GianoError } from "../giano-error";
import {
	type ToGianoSmartAccountParameters,
	type ToGianoSmartAccountReturnType,
	toGianoSmartAccount,
} from "./toGianoSmartAccount";

/** The credential cannot sign for the smart account it was asked to connect to. */
export class GianoAccountOwnerError extends GianoError {}

export type ConnectGianoSmartAccountParameters = {
	client: ToGianoSmartAccountParameters["client"];
	owner: WebAuthnAccount;
	factoryAddress: Address;
	/**
	 * The smart account to connect to. When not provided, the account is the address derived
	 * from `owner`, and nothing is checked.
	 */
	address?: Address | undefined;
};

/**
 * Builds the Giano smart account that one passkey connects to.
 *
 * With an `address`, the account is bound to that address only after a check that `owner` can
 * sign for it:
 * - a deployed account must list the passkey as an owner (`isOwnerBytes`);
 * - an account that is not deployed yet has only the owners in its factory salt, so `address`
 *   must be the passkey's own derived address.
 *
 * It throws {@link GianoAccountOwnerError} when the check fails. It never falls back to the
 * derived address: for a secondary owner that is a different, empty account.
 */
export async function connectGianoSmartAccount({
	client,
	owner,
	factoryAddress,
	address,
}: ConnectGianoSmartAccountParameters): Promise<ToGianoSmartAccountReturnType> {
	if (address === undefined) {
		return toGianoSmartAccount({ client, owners: [owner], factoryAddress });
	}

	const account = await toGianoSmartAccount({
		client,
		owners: [owner],
		factoryAddress,
		address,
	});

	if (await account.isDeployed()) {
		const isOwner = await readContract(client, {
			address,
			abi: gianoSmartWalletAbi,
			functionName: "isOwnerBytes",
			args: [owner.publicKey],
		});
		if (!isOwner) {
			throw new GianoAccountOwnerError(
				`This passkey is not an owner of the smart account ${address}.`,
			);
		}
		return account;
	}

	const derivedAddress = await (
		await toGianoSmartAccount({ client, owners: [owner], factoryAddress })
	).getAddress();
	if (!isAddressEqual(derivedAddress, address)) {
		throw new GianoAccountOwnerError(
			`The smart account ${address} is not deployed, and it is not this passkey's own account (${derivedAddress}). A passkey added as an owner can connect only to a deployed account.`,
		);
	}
	return account;
}
