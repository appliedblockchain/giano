import { randomBytes } from "node:crypto";
import {
	type Address,
	bytesToHex,
	encodeAbiParameters,
	encodeFunctionData,
	type Hex,
	hexToBytes,
	maxUint256,
	type PublicClient,
	parseAbi,
	serializeTransaction,
	size,
} from "viem";
import { entryPoint07Abi } from "viem/account-abstraction";
import { packUserOp, type UserOp } from "./userop.js";

/**
 * preVerificationGas: the flat gas an operation pays for everything the EntryPoint cannot meter —
 * the 21 000 transaction base, its calldata, the handleOps loop around it and the beneficiary
 * transfer, plus on an OP-stack chain the L1 data fee. The executor is reimbursed through it, so
 * too low is a loss on every operation.
 *
 * The overheads are Alto's (and the eth-infinitism reference bundler's) defaults, for one
 * operation per handleOps transaction.
 */
const OVERHEAD = {
	fixed: 21_000n,
	perUserOp: 18_300n,
	perUserOpWord: 4n,
	zeroByte: 4n,
	nonZeroByte: 16n,
};

const packedFields = [
	{ type: "address" },
	{ type: "uint256" },
	{ type: "bytes" },
	{ type: "bytes" },
	{ type: "bytes32" },
	{ type: "uint256" },
	{ type: "bytes32" },
	{ type: "bytes" },
	{ type: "bytes" },
] as const;

const filled = (bytes: number): Hex =>
	bytesToHex(new Uint8Array(bytes).fill(0xff));

/**
 * Calldata gas of the packed operation, with every gas field at its maximum width so the figure
 * does not move when the limits are filled in afterwards.
 *
 * `estimate` sizes the signature and paymaster data the way Alto did — one 0xff byte per
 * character of their hex string, so roughly twice their length. During estimation both are stubs,
 * and a WebAuthn signature is longer than Giano's stub (the owner bytes and a real clientDataJSON),
 * so the estimate has to leave room for the signature the operation will actually carry. The
 * submission check measures the real bytes, which therefore always fits under an estimate.
 */
export function staticPreVerificationGas(
	op: UserOp,
	mode: "estimate" | "exact",
): bigint {
	const packed = packUserOp(op);
	const bytesOf = (value: Hex) =>
		mode === "estimate" ? value.length : (value.length - 2) / 2;
	const max32 = `0x${"ff".repeat(32)}` as Hex;
	const encoded = hexToBytes(
		encodeAbiParameters(packedFields, [
			packed.sender,
			maxUint256,
			packed.initCode,
			packed.callData,
			max32,
			maxUint256,
			max32,
			filled(bytesOf(packed.paymasterAndData)),
			filled(bytesOf(packed.signature)),
		]),
	);
	let calldataGas = 0n;
	for (const byte of encoded)
		calldataGas += byte === 0 ? OVERHEAD.zeroByte : OVERHEAD.nonZeroByte;
	const words = BigInt(Math.ceil(encoded.length / 32));
	return (
		calldataGas +
		OVERHEAD.fixed +
		OVERHEAD.perUserOp +
		OVERHEAD.perUserOpWord * words
	);
}

/** The OP-stack GasPriceOracle predeploy: its presence is what makes a chain OP-stack here. */
export const GAS_PRICE_ORACLE: Address =
	"0x420000000000000000000000000000000000000F";
const gasPriceOracleAbi = parseAbi([
	"function getL1Fee(bytes _data) view returns (uint256)",
]);

/**
 * The L1 data fee of this operation's handleOps transaction, expressed in L2 gas at the
 * operation's own gas price — the price the executor is reimbursed at.
 */
export async function l1FeeGas(
	client: PublicClient,
	op: UserOp,
	entryPoint: Address,
	beneficiary: Address,
	chainId: number,
): Promise<bigint> {
	// A stub signature is mostly zeros, which compresses better than the real one will: random
	// bytes of the same length are the honest stand-in.
	const priced = {
		...op,
		signature: bytesToHex(randomBytes(Math.max(size(op.signature), 65))),
	};
	const serialized = serializeTransaction({
		chainId,
		type: "eip1559",
		to: entryPoint,
		data: encodeFunctionData({
			abi: entryPoint07Abi,
			functionName: "handleOps",
			args: [[packUserOp(priced)], beneficiary],
		}),
		nonce: 0xffff,
		gas: 10_000_000n,
		maxFeePerGas: op.maxFeePerGas,
		maxPriorityFeePerGas: op.maxPriorityFeePerGas,
	});
	const [l1Fee, block] = await Promise.all([
		client.readContract({
			address: GAS_PRICE_ORACLE,
			abi: gasPriceOracleAbi,
			functionName: "getL1Fee",
			args: [serialized],
		}),
		client.getBlock({ blockTag: "latest" }),
	]);
	const baseFee = block.baseFeePerGas ?? 0n;
	const price = minBigInt(op.maxFeePerGas, baseFee + op.maxPriorityFeePerGas);
	if (price === 0n) return 0n;
	return (l1Fee + price - 1n) / price;
}

export function scale(value: bigint, percent: bigint): bigint {
	return (value * percent) / 100n;
}

export function minBigInt(a: bigint, b: bigint): bigint {
	return a < b ? a : b;
}

export function maxBigInt(a: bigint, b: bigint): bigint {
	return a > b ? a : b;
}
