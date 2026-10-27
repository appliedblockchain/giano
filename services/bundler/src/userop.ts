import { type Address, getAddress, type Hex } from "viem";
import {
	getUserOperationHash,
	toPackedUserOperation,
	type UserOperation,
} from "viem/account-abstraction";
import { z } from "zod";

const hexData = z
	.string()
	.regex(
		/^0x([0-9a-fA-F]{2})*$/,
		"expected 0x-prefixed hex bytes",
	) as unknown as z.ZodType<Hex>;
const hexQuantity = z
	.string()
	.regex(
		/^0x[0-9a-fA-F]{1,64}$/,
		"expected a 0x-prefixed hex quantity",
	) as unknown as z.ZodType<Hex>;
export const addressSchema = z
	.string()
	.regex(
		/^0x[0-9a-fA-F]{40}$/,
		"expected an address",
	) as unknown as z.ZodType<Address>;
export const hash32Schema = z
	.string()
	.regex(
		/^0x[0-9a-fA-F]{64}$/,
		"expected a 32-byte hash",
	) as unknown as z.ZodType<Hex>;

const quantity = hexQuantity.transform((value) => BigInt(value));

/** Fields every v0.9 operation carries, in JSON-RPC (hex) encoding. */
const base = {
	// Giano uses factory-deployed passkey accounts and its existing sponsorship envelope.
	authorization: z.never().optional(),
	eip7702Auth: z.never().optional(),
	paymasterSignature: z.never().optional(),
	sender: addressSchema.transform((value) => getAddress(value)),
	nonce: quantity,
	callData: hexData,
	factory: addressSchema.transform((value) => getAddress(value)).optional(),
	factoryData: hexData.optional(),
	paymaster: addressSchema.transform((value) => getAddress(value)).optional(),
	paymasterData: hexData.optional(),
};

/** An operation submitted for inclusion: every gas field and the signature are required. */
export const signedUserOpSchema = z
	.object({
		...base,
		callGasLimit: quantity,
		verificationGasLimit: quantity,
		preVerificationGas: quantity,
		maxFeePerGas: quantity,
		maxPriorityFeePerGas: quantity,
		paymasterVerificationGasLimit: quantity.optional(),
		paymasterPostOpGasLimit: quantity.optional(),
		signature: hexData,
	})
	.strip();

/** An operation being estimated: gas fields are what is asked for, so any may be absent or zero. */
export const estimateUserOpSchema = z
	.object({
		...base,
		callGasLimit: quantity.optional(),
		verificationGasLimit: quantity.optional(),
		preVerificationGas: quantity.optional(),
		maxFeePerGas: quantity.optional(),
		maxPriorityFeePerGas: quantity.optional(),
		paymasterVerificationGasLimit: quantity.optional(),
		paymasterPostOpGasLimit: quantity.optional(),
		signature: hexData.optional(),
	})
	.strip();

export type UserOp = UserOperation<"0.9">;

/** Normalises a parsed operation: the factory and paymaster fields travel as complete groups or not at all. */
export function toUserOp(
	parsed:
		| z.infer<typeof signedUserOpSchema>
		| z.infer<typeof estimateUserOpSchema>,
): UserOp {
	const op: UserOp = {
		sender: parsed.sender,
		nonce: parsed.nonce,
		callData: parsed.callData,
		callGasLimit: parsed.callGasLimit ?? 0n,
		verificationGasLimit: parsed.verificationGasLimit ?? 0n,
		preVerificationGas: parsed.preVerificationGas ?? 0n,
		maxFeePerGas: parsed.maxFeePerGas ?? 0n,
		maxPriorityFeePerGas: parsed.maxPriorityFeePerGas ?? 0n,
		signature: parsed.signature ?? "0x",
	};
	if (parsed.factory) {
		op.factory = parsed.factory;
		op.factoryData = parsed.factoryData ?? "0x";
	}
	if (parsed.paymaster) {
		op.paymaster = parsed.paymaster;
		op.paymasterData = parsed.paymasterData ?? "0x";
		op.paymasterVerificationGasLimit =
			parsed.paymasterVerificationGasLimit ?? 0n;
		op.paymasterPostOpGasLimit = parsed.paymasterPostOpGasLimit ?? 0n;
	}
	return op;
}

export function userOpHash(
	op: UserOp,
	entryPoint: Address,
	chainId: number,
): Hex {
	return getUserOperationHash({
		chainId,
		entryPointAddress: entryPoint,
		entryPointVersion: "0.9",
		userOperation: op,
	});
}

export function packUserOp(op: UserOp) {
	return toPackedUserOperation(op);
}

const hex = (value: bigint): Hex => `0x${value.toString(16)}`;

/** The operation back in JSON-RPC encoding, absent groups omitted — as Alto returned it. */
export function formatUserOp(op: UserOp): Record<string, Hex | Address> {
	return {
		sender: op.sender,
		nonce: hex(op.nonce),
		...(op.factory
			? { factory: op.factory, factoryData: op.factoryData ?? "0x" }
			: {}),
		callData: op.callData,
		callGasLimit: hex(op.callGasLimit),
		verificationGasLimit: hex(op.verificationGasLimit),
		preVerificationGas: hex(op.preVerificationGas),
		maxFeePerGas: hex(op.maxFeePerGas),
		maxPriorityFeePerGas: hex(op.maxPriorityFeePerGas),
		...(op.paymaster
			? {
					paymaster: op.paymaster,
					paymasterVerificationGasLimit: hex(
						op.paymasterVerificationGasLimit ?? 0n,
					),
					paymasterPostOpGasLimit: hex(op.paymasterPostOpGasLimit ?? 0n),
					paymasterData: op.paymasterData ?? "0x",
				}
			: {}),
		signature: op.signature,
	};
}

/** ERC-4337 2-D nonce: the high 192 bits select a lane, the low 64 count within it. */
export function nonceKey(nonce: bigint): bigint {
	return nonce >> 64n;
}

export function nonceSequence(nonce: bigint): bigint {
	return nonce & 0xffffffffffffffffn;
}
