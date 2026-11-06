/**
 * ERC-1967 proxies (the paymaster proxy): which implementation a proxy delegates to. One reader for
 * the deploy tooling, giano-doctor and wallet-api, whatever client they use.
 */
import { type Address, getAddress, type PublicClient } from "viem";

/** bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1). */
export const IMPLEMENTATION_SLOT =
	"0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

/**
 * The implementation address a raw implementation-slot word holds (the low 20 bytes), or null when
 * the slot is empty or zero. Takes the word as any client returns it: 32 bytes, shorter, or "0x".
 */
export function implementationFromSlot(
	word: string | null | undefined,
): Address | null {
	if (!word || !/^0x[0-9a-fA-F]*$/.test(word)) return null;
	const low = word.slice(2).padStart(40, "0").slice(-40);
	return /^0+$/.test(low) ? null : getAddress(`0x${low}`);
}

/** The implementation the ERC-1967 proxy at `proxy` delegates to, or null when its slot is empty. */
export async function proxyImplementation(
	client: Pick<PublicClient, "getStorageAt">,
	proxy: Address,
): Promise<Address | null> {
	return implementationFromSlot(
		await client.getStorageAt({ address: proxy, slot: IMPLEMENTATION_SLOT }),
	);
}
