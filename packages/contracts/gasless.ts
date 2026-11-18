/**
 * Whether a chain charges nothing for gas, so that a user operation with a fee of 0 is the correct
 * fee (H6). giano-bundler refuses a fee of 0 at estimation and at submission unless this is true,
 * and wallet-api's `pm_getPaymasterData` refuses to sponsor one. All three use this one check.
 *
 * A chain charges nothing when:
 * - its gas price is 0: the latest block's base fee, where blocks carry one, and `eth_gasPrice`.
 *   A base fee of 0 is not enough on its own: a node can still require a tip (geth's
 *   `--txpool.pricelimit`), and `eth_gasPrice` then answers above 0;
 * - and, on an OP Stack chain, its L1 data fee is also 0. The executor pays that fee, and the
 *   user operation repays it only through its gas price, so at a fee of 0 nobody would.
 */
import {
	type Address,
	decodeFunctionResult,
	encodeFunctionData,
	type Hex,
} from "viem";

/** The OP Stack GasPriceOracle predeploy: a chain with code here is an OP Stack chain. */
export const GAS_PRICE_ORACLE: Address =
	"0x420000000000000000000000000000000000000F";

const getL1FeeAbi = [
	{
		type: "function",
		name: "getL1Fee",
		stateMutability: "view",
		inputs: [{ name: "_data", type: "bytes" }],
		outputs: [{ name: "", type: "uint256" }],
	},
] as const;

/** Stands in for a transaction: any data has an L1 fee above 0 on a chain whose L1 fee is not 0. */
const SAMPLE_TRANSACTION: Hex = `0x${"ff".repeat(200)}`;

/** The reads {@link chargesNoGas} needs. A viem `PublicClient` has them all. */
export type GasPriceReader = {
	getBlock(): Promise<{ baseFeePerGas?: bigint | null }>;
	getGasPrice(): Promise<bigint>;
	getCode(parameters: { address: Address }): Promise<Hex | undefined>;
	call(parameters: { to: Address; data: Hex }): Promise<{ data?: Hex }>;
};

/**
 * True when the chain charges nothing for gas (see the module comment). Reads only what it needs:
 * a chain that charges a base fee costs one block read, and `eth_gasPrice` is read only after that.
 * A failed read is thrown, never taken as "gasless".
 *
 * @param options.block - the latest block, when the caller has already read it.
 * @param options.opStack - whether the chain is OP Stack, when the caller knows it; otherwise the
 *   GasPriceOracle predeploy is looked up.
 */
export async function chargesNoGas(
	client: GasPriceReader,
	options: {
		block?: { baseFeePerGas?: bigint | null };
		opStack?: boolean;
	} = {},
): Promise<boolean> {
	const block = options.block ?? (await client.getBlock());
	if (block.baseFeePerGas != null && block.baseFeePerGas > 0n) return false;
	if ((await client.getGasPrice()) > 0n) return false;

	const opStack =
		options.opStack ??
		hasCode(await client.getCode({ address: GAS_PRICE_ORACLE }));
	if (!opStack) return true;

	const { data } = await client.call({
		to: GAS_PRICE_ORACLE,
		data: encodeFunctionData({
			abi: getL1FeeAbi,
			functionName: "getL1Fee",
			args: [SAMPLE_TRANSACTION],
		}),
	});
	if (!data || data === "0x")
		throw new Error(
			`the GasPriceOracle at ${GAS_PRICE_ORACLE} returned no L1 fee`,
		);
	return (
		decodeFunctionResult({
			abi: getL1FeeAbi,
			functionName: "getL1Fee",
			data,
		}) === 0n
	);
}

function hasCode(code: Hex | undefined): boolean {
	return code !== undefined && code !== "0x";
}
