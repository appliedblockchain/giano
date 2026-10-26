import {
	type Address,
	decodeFunctionResult,
	encodeFunctionData,
	getContractAddress,
	type Hex,
	type PublicClient,
	type StateOverride,
	size,
	sliceHex,
	zeroAddress,
} from "viem";
import type { ChainType } from "./config.js";
import {
	decodeEntryPointRevert,
	ERROR_CODES,
	RpcError,
	simulationError,
} from "./errors.js";
import {
	entryPointSimulationsAbi,
	entryPointSimulationsCode,
	senderCreatorCode,
} from "./generated/simulations.js";
import { l1FeeGas, maxBigInt, scale, staticPreVerificationGas } from "./pvg.js";
import { packUserOp, type UserOp } from "./userop.js";

/**
 * Gas estimation by simulation. The EntryPoint's own code is swapped for the eth-infinitism
 * `EntryPointSimulations` in an eth_call state override, so the simulation runs against the real
 * EntryPoint's storage — deposits, nonces, deployed accounts — and needs nothing deployed.
 *
 * Every simulation prices the operation at 1 wei per gas. The EntryPoint then reports `paid` in
 * gas units, and the execution gas falls out of it exactly (see `executionGasUsed`); the prefund
 * is a few million wei, which any real paymaster deposit covers.
 */

export type GasEstimate = {
	preVerificationGas: bigint;
	verificationGasLimit: bigint;
	callGasLimit: bigint;
	paymasterVerificationGasLimit: bigint;
	paymasterPostOpGasLimit: bigint;
};

/** Limits the simulation runs with, raised to the caller's own where those are higher. */
const SIMULATION = {
	verificationGasLimit: 4_000_000n,
	callGasLimit: 6_000_000n,
	paymasterVerificationGasLimit: 1_000_000n,
	paymasterPostOpGasLimit: 500_000n,
};
/** `innerHandleOp` refuses to start unless 63/64 of what is left covers the execution limits plus this. */
const INNER_GAS_OVERHEAD = 10_000n;
/** EntryPoint v0.7 charges 10% of unused execution gas. */
const PENALTY_PERCENT = 10n;
const MIN_CALL_GAS = 9_000n;
/** Assumed for a paymaster that did not say what its postOp needs. */
const DEFAULT_POST_OP_GAS = 50_000n;
const EXECUTE_USER_OP_SELECTOR = "0x8dd7712f";

export type Estimator = ReturnType<typeof createEstimator>;

export function createEstimator(options: {
	client: PublicClient;
	entryPoint: Address;
	chainId: number;
	chainType: ChainType;
	/** `from` for the simulations, and the beneficiary the L1-fee transaction is sized for. */
	executor: Address;
}) {
	const { client, entryPoint, chainId, chainType, executor } = options;
	// The SenderCreator EntryPointSimulations derives: the EntryPoint's first CREATE. A canonical
	// deployment has it there already; anvil_setCode'd devnets do not, so it is always provided.
	const senderCreator = getContractAddress({ from: entryPoint, nonce: 1n });

	const overrides = async (
		op: UserOp,
		fundSender: boolean,
	): Promise<StateOverride> => {
		const list: StateOverride = [
			{ address: entryPoint, code: entryPointSimulationsCode },
			{ address: senderCreator, code: senderCreatorCode },
		];
		// At 1 wei per gas the prefund is tiny, but a counterfactual account holds nothing at all:
		// fund just that much on top of whatever it has, so execution still sees its real balance.
		if (fundSender && !op.paymaster) {
			const balance = await client.getBalance({ address: op.sender });
			list.push({ address: op.sender, balance: balance + prefund(op) });
		}
		return list;
	};

	const call = async (
		functionName: "simulateHandleOp" | "simulateValidation",
		args: readonly unknown[],
		op: UserOp,
		fundSender: boolean,
	) => {
		const data = encodeFunctionData({
			abi: entryPointSimulationsAbi,
			functionName,
			args,
		} as never);
		const gas =
			op.verificationGasLimit +
			(op.paymasterVerificationGasLimit ?? 0n) +
			((op.callGasLimit +
				(op.paymasterPostOpGasLimit ?? 0n) +
				INNER_GAS_OVERHEAD) *
				64n) /
				63n +
			1_000_000n;
		try {
			const result = await client.call({
				account: executor,
				to: entryPoint,
				data,
				gas,
				stateOverride: await overrides(op, fundSender),
			});
			return result.data ?? "0x";
		} catch (error) {
			const revert = decodeEntryPointRevert(error);
			throw simulationError(
				revert.kind === "failed-op"
					? revert.reason + innerSuffix(revert.inner)
					: revert.message,
			);
		}
	};

	const simulateHandleOp = async (
		op: UserOp,
		target: Address = zeroAddress,
		targetCallData: Hex = "0x",
	) => {
		const data = await call(
			"simulateHandleOp",
			[packUserOp(op), target, targetCallData],
			op,
			true,
		);
		return decodeFunctionResult({
			abi: entryPointSimulationsAbi,
			functionName: "simulateHandleOp",
			data,
		});
	};

	return {
		async estimate(input: UserOp): Promise<GasEstimate> {
			if (input.maxFeePerGas === 0n) {
				throw new RpcError(
					ERROR_CODES.invalidParams,
					"user operation max fee per gas must be larger than 0 during gas estimation",
				);
			}
			const hasPaymaster = Boolean(input.paymaster);
			const givenPaymasterVerification =
				input.paymasterVerificationGasLimit || undefined;
			const givenPostOp = input.paymasterPostOpGasLimit || undefined;

			const simOp: UserOp = {
				...input,
				maxFeePerGas: 1n,
				maxPriorityFeePerGas: 1n,
				preVerificationGas: 0n,
				verificationGasLimit: maxBigInt(
					input.verificationGasLimit,
					SIMULATION.verificationGasLimit,
				),
				callGasLimit: maxBigInt(input.callGasLimit, SIMULATION.callGasLimit),
				...(hasPaymaster
					? {
							paymasterVerificationGasLimit: maxBigInt(
								givenPaymasterVerification ?? 0n,
								SIMULATION.paymasterVerificationGasLimit,
							),
							paymasterPostOpGasLimit: maxBigInt(
								givenPostOp ?? 0n,
								SIMULATION.paymasterPostOpGasLimit,
							),
						}
					: {}),
			};

			const hasCall = size(input.callData) > 0;
			// A second simulation runs the call on its own, from the EntryPoint, after validation (and
			// deployment) — the one way stock EntryPointSimulations reports whether it reverts.
			const checkCall =
				hasCall && sliceHex(input.callData, 0, 4) !== EXECUTE_USER_OP_SELECTOR;
			const [measured, probe] = await Promise.all([
				simulateHandleOp(simOp),
				checkCall
					? simulateHandleOp(
							{ ...simOp, callData: "0x" },
							input.sender,
							input.callData,
						).catch(() => undefined)
					: undefined,
			]);
			// An account may refuse empty callData in validation; then the probe says nothing.
			if (probe && !probe.targetSuccess)
				throw simulationError(describeRevert(probe.targetResult));

			const preOpGas = measured.preOpGas;
			const used = executionGasUsed(
				measured.paid - preOpGas,
				simOp.callGasLimit + (simOp.paymasterPostOpGasLimit ?? 0n),
			);

			// preOpGas covers the account's validation (and deployment) and the paymaster's, so it bounds
			// either limit on its own.
			const verificationGasLimit = scale(preOpGas, 130n);
			const paymasterVerificationGasLimit = hasPaymaster
				? (givenPaymasterVerification ?? scale(preOpGas, 130n))
				: 0n;
			const paymasterPostOpGasLimit = hasPaymaster
				? (givenPostOp ?? DEFAULT_POST_OP_GAS)
				: 0n;

			let callGasLimit = 0n;
			if (hasCall) {
				callGasLimit = maxBigInt(MIN_CALL_GAS, scale(used, 110n));
				// `used` is what the call took with gas to spare; a call that forwards gas onward can need
				// more than it uses. Re-run at the chosen limit: running out shows up as the call eating
				// the whole limit, well above what it used before.
				for (let attempt = 0; attempt < 3; attempt++) {
					const atLimit = {
						...simOp,
						callGasLimit,
						...(hasPaymaster ? { paymasterPostOpGasLimit } : {}),
					};
					const result = await simulateHandleOp(atLimit);
					const usedAtLimit = executionGasUsed(
						result.paid - result.preOpGas,
						callGasLimit + (hasPaymaster ? paymasterPostOpGasLimit : 0n),
					);
					if (usedAtLimit <= used + (callGasLimit - used) / 2n) break;
					callGasLimit = scale(callGasLimit, 150n);
				}
			}

			const estimated: UserOp = {
				...input,
				verificationGasLimit,
				callGasLimit,
				...(hasPaymaster
					? { paymasterVerificationGasLimit, paymasterPostOpGasLimit }
					: {}),
			};

			// Finally validate at the real price with no help: an account that cannot pay its prefund,
			// or a paymaster whose deposit cannot cover it, is reported now rather than at submission.
			await call(
				"simulateValidation",
				[
					packUserOp({
						...estimated,
						preVerificationGas: staticPreVerificationGas(estimated, "estimate"),
					}),
				],
				estimated,
				false,
			);

			let preVerificationGas = scale(
				staticPreVerificationGas(estimated, "estimate"),
				110n,
			);
			if (chainType === "op-stack") {
				preVerificationGas += scale(
					await l1FeeGas(
						client,
						{ ...estimated, preVerificationGas },
						entryPoint,
						executor,
						chainId,
					),
					125n,
				);
			}

			return {
				preVerificationGas,
				verificationGasLimit,
				callGasLimit,
				paymasterVerificationGasLimit,
				paymasterPostOpGasLimit,
			};
		},
	};
}

/**
 * Execution gas from what the EntryPoint charged beyond validation. It charges
 * `used + (limit - used) / 10` (the unused-gas penalty), so `used = (10·charged - limit) / 9`;
 * with nothing unused there is no penalty and the charge is the usage.
 */
export function executionGasUsed(charged: bigint, limit: bigint): bigint {
	if (charged >= limit) return charged;
	const used =
		(100n * charged - PENALTY_PERCENT * limit) / (100n - PENALTY_PERCENT);
	return used < 0n ? 0n : used;
}

function prefund(op: UserOp): bigint {
	const gas =
		op.verificationGasLimit +
		op.callGasLimit +
		(op.paymasterVerificationGasLimit ?? 0n) +
		(op.paymasterPostOpGasLimit ?? 0n) +
		op.preVerificationGas;
	return gas * op.maxFeePerGas;
}

function innerSuffix(inner: Hex | undefined): string {
	return inner && inner !== "0x" ? ` - ${describeRevert(inner)}` : "";
}

const ERROR_STRING = "0x08c379a0";

/** Error(string) decoded; anything else as raw hex. */
export function describeRevert(data: Hex): string {
	if (data.startsWith(ERROR_STRING) && size(data) >= 68) {
		try {
			const length = Number(BigInt(sliceHex(data, 36, 68)));
			const bytes = Buffer.from(
				sliceHex(data, 68, 68 + length).slice(2),
				"hex",
			);
			return bytes.toString("utf8");
		} catch {
			return data;
		}
	}
	return data === "0x" ? "execution reverted" : data;
}
