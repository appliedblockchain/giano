import type { PaymasterPublicClient } from "./client";

/**
 * A simulated write with headroom on its gas limit.
 *
 * A node's estimate can be exactly the gas a call is charged after refunds — enough to pay for it,
 * not to run it. A call that clears storage (cancelling a timelock operation, revoking a role) uses
 * more while it runs than it is finally charged, and a transaction sent with the bare estimate runs
 * out of gas and reverts. Wallets differ in whether they pad an estimate; this does not leave it to
 * them. A fifth more covers the refund, and the sender only pays for what is used.
 */
export async function withGasHeadroom<T extends object>(
	publicClient: PaymasterPublicClient,
	request: T,
): Promise<T & { gas: bigint }> {
	const estimate = await publicClient.estimateContractGas(request as never);
	return { ...request, gas: estimate + estimate / 5n };
}
