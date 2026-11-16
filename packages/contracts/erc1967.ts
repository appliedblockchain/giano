/**
 * ERC-1967 proxies (the paymaster proxy): which implementation a proxy delegates to. One reader for
 * the deploy tooling, giano-doctor and wallet-api, whatever client they use.
 */
import { type Address, getAddress, type Hex, type PublicClient } from "viem";

/** bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1). */
export const IMPLEMENTATION_SLOT =
	"0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

/** keccak256("Upgraded(address)"): the event ERC-1967 emits each time the implementation changes. */
export const UPGRADED_TOPIC: Hex =
	"0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b";

/** The widest block span one `eth_getLogs` request covers when the slot cannot be read. */
export const UPGRADED_LOG_CHUNK = 10_000n;

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

/**
 * The implementation named by the proxy's latest `Upgraded` event, or null when it emitted none.
 * For an RPC that refuses `eth_getStorageAt` (Silent Data): walks back from `latest` in chunks of
 * {@link UPGRADED_LOG_CHUNK} blocks and stops at the first chunk that holds an upgrade.
 * `getLogs` returns the topics of the proxy's `Upgraded` logs in [fromBlock, toBlock], oldest first.
 */
export async function implementationFromUpgradedLogs(
	getLogs: (
		fromBlock: bigint,
		toBlock: bigint,
	) => Promise<readonly { topics: readonly (string | null)[] }[]>,
	latest: bigint,
): Promise<Address | null> {
	for (let to = latest; to >= 0n; to -= UPGRADED_LOG_CHUNK) {
		const from =
			to >= UPGRADED_LOG_CHUNK - 1n ? to - UPGRADED_LOG_CHUNK + 1n : 0n;
		const logs = await getLogs(from, to);
		const last = logs.at(-1);
		if (last) return implementationFromSlot(last.topics[1]);
	}
	return null;
}

/**
 * The implementation the ERC-1967 proxy at `proxy` delegates to, or null when its slot is empty.
 * Reads the slot. When the RPC refuses that and the client can read logs, falls back to the latest
 * `Upgraded` event.
 */
export async function proxyImplementation(
	client: Pick<PublicClient, "getStorageAt"> &
		Partial<Pick<PublicClient, "getBlockNumber" | "request">>,
	proxy: Address,
): Promise<Address | null> {
	try {
		return implementationFromSlot(
			await client.getStorageAt({ address: proxy, slot: IMPLEMENTATION_SLOT }),
		);
	} catch (error) {
		const { getBlockNumber, request } = client;
		if (!getBlockNumber || !request) throw error;
		return implementationFromUpgradedLogs(
			(fromBlock, toBlock) =>
				request({
					method: "eth_getLogs",
					params: [
						{
							address: proxy,
							topics: [UPGRADED_TOPIC],
							fromBlock: `0x${fromBlock.toString(16)}`,
							toBlock: `0x${toBlock.toString(16)}`,
						},
					],
				}) as Promise<readonly { topics: readonly (string | null)[] }[]>,
			await getBlockNumber(),
		);
	}
}
