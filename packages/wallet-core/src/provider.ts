import { v4 as uuidv4 } from "uuid";
import type {
	EIP1193EventMap,
	EIP1193Parameters,
	EIP1193RequestFn,
	EIP1474Methods,
} from "viem";
import {
	type Address,
	BaseError,
	type Call,
	type Chain,
	ContractFunctionRevertedError,
	concatHex,
	createPublicClient,
	type EIP1193Provider,
	type ExactPartial,
	type Hash,
	type Hex,
	hexToBytes,
	isHex,
	type PublicClient,
	parseGwei,
	type RpcTransactionRequest,
	stringToBytes,
	type TransactionRequest,
	type Transport,
	toHex,
} from "viem";
import type {
	BundlerClient,
	SendUserOperationParameters,
	SmartAccount,
	UserOperation,
	UserOperationReceipt,
} from "viem/account-abstraction";
import {
	createWebAuthnCredential,
	sendUserOperation,
	toWebAuthnAccount,
} from "viem/account-abstraction";
import type { GianoSmartAccountImplementation } from "./account";
import {
	getWebAuthnAccount,
	STATIC_CALL_SIGNED_AT_BACKDATE_SECONDS,
	toGianoSmartAccount,
} from "./account";
import {
	ensureSmartAccountIsDeployed,
	isSmartAccountDeployed,
} from "./account/deployment";
import {
	GianoEntryPointAddress,
	type GianoEntryPointVersion,
} from "./giano-entry-point";
import { GianoError } from "./giano-error";
import type { GianoLogger } from "./logger";
import { defaultGianoLogger } from "./logger";
import {
	type PasskeyDevicePreference,
	passkeyCredentialCreate,
	passkeyCredentialGet,
	resolvePasskeyDevicePreference,
} from "./passkey-device-preference";
import {
	DEFAULT_RESIDENT_KEY_REQUIREMENT,
	DEFAULT_USER_VERIFICATION_REQUIREMENT,
	type GianoProviderInjection,
} from "./provider-injection";
import { withValidation } from "./provider-injection/_with-validation";
import { toBase64Url } from "./provider-injection/wallet-api/serialization";

/**
 * Chain family encoded into the WebAuthn user id (1 byte). EVM covers every chain Giano
 * currently deploys to; the byte exists so a future non-EVM family can be distinguished
 * without changing the id layout. `HARDHAT` is kept as a deprecated alias of the EVM
 * value so existing encoded ids keep decoding.
 */
export enum ChainType {
	EVM = 0,
	/** @deprecated use EVM — retained as a 0-valued alias for backward compatibility */
	HARDHAT = 0,
}

type PrepareUserOperationOptions = Partial<
	Omit<
		SendUserOperationParameters<
			SmartAccount<GianoSmartAccountImplementation>,
			undefined,
			TransactionRequest[]
		>,
		"account" | "calls" | "callData"
	>
>;

export const isChainType = (x: unknown): x is ChainType => {
	return typeof x === "number" && Object.values(ChainType).includes(x);
};

function extractXYCoords(key: Uint8Array | Hex): { x: Hex; y: Hex } {
	if (key instanceof Uint8Array) {
		key = toHex(key.slice(-64), { size: 64 });
	}
	return { x: `0x${key.slice(-128, -64)}`, y: `0x${key.slice(-64)}` };
}

export type CreateGianoProviderParams = {
	passkeyDevicePreference?: PasskeyDevicePreference;
	initialChainId: number;
	/**
	 * One bundler per chain. A map even when one chain is configured: submission is a
	 * chain-bound resource, and no operation for one chain may ever be submitted through
	 * another chain's endpoint (MC-43, MC-58).
	 */
	bundlers: Record<number, BundlerClient>;
	chains: readonly Chain[];
	transports: Record<number, Transport> | undefined;
	injection: GianoProviderInjection;
	/**
	 * One factory address per chain. Deliberately a map even though address identity (MC-19)
	 * guarantees the values are equal on a canonical deployment: passing one address would
	 * encode the invariant in the type where nothing checks it, and a deployment that is NOT
	 * address-identical must still be expressible.
	 */
	factoryAddresses: Record<number, Address>;
	/** Optional logger; defaults to silent-except-errors. */
	logger?: GianoLogger;
	/**
	 * Fallback fee estimation used when neither the request nor the bundler's
	 * prepared op carries fees, resolved per chain — fee levels differ between chains
	 * by orders of magnitude, so one figure cannot serve them all.
	 */
	estimateFeesPerGas?: (
		chainId: number,
	) => Promise<{ maxFeePerGas: bigint; maxPriorityFeePerGas: bigint }>;
};

type EventHandler<E extends keyof EIP1193EventMap> = (
	payload: Parameters<EIP1193EventMap[E]>[0],
) => void;
type EventListeners = {
	[E in keyof EIP1193EventMap]: Set<EventHandler<E>>;
};

type GianoProviderCustomMethods = [
	{
		Method: "waitForUserOperationReceipt";
		Parameters: [hash: Hash];
		ReturnType: UserOperationReceipt;
	},
	{
		/**
		 * Silently rebuilds the in-memory smart account from the stored public key and the
		 * persisted wallet-api session — no passkey ceremony. Used to recover a connected
		 * account after the wallet page was reloaded/reopened. Returns the account address,
		 * or an empty array when it cannot be restored without a fresh sign-in.
		 */
		Method: "giano_restoreAccount";
		Parameters: [];
		ReturnType: Address[];
	},
	{
		Method: "signed_eth_call";
		Parameters: readonly [call: ExactPartial<RpcTransactionRequest>];
		ReturnType: Hex;
	},
	{
		Method: "eth_prepareUserOperation";
		Parameters: [calls: Call[], options?: PrepareUserOperationOptions];
		ReturnType: UserOperation<GianoEntryPointVersion>;
	},
	{
		Method: "eth_signUserOperation";
		Parameters: [userOp: UserOperation<GianoEntryPointVersion>];
		ReturnType: Hex;
	},
	{
		Method: "eth_sendSignedUserOperation";
		Parameters: [signedUserOp: UserOperation<GianoEntryPointVersion>];
		ReturnType: Hash;
	},
];

export type ProviderRequestMethod<
	T extends EIP1474Methods | GianoProviderCustomMethods,
	Name extends T[number]["Method"],
> = (
	params: Extract<T[number], { Method: Name }>["Parameters"],
) => Promise<Extract<T[number], { Method: Name }>["ReturnType"]>;

/**
 * EIP1474 methods as optional
 * Giano custom methods as required
 **/
type GianoProviderMethodsMap = Partial<{
	[T in EIP1474Methods[number] as T["Method"]]: ProviderRequestMethod<
		EIP1474Methods,
		T["Method"]
	>;
}> &
	Required<{
		[T in GianoProviderCustomMethods[number] as T["Method"]]: ProviderRequestMethod<
			GianoProviderCustomMethods,
			T["Method"]
		>;
	}>;

export type GianoProvider = EIP1193Provider & {
	request: EIP1193RequestFn<GianoProviderCustomMethods>;
	getSmartAccount: () => SmartAccount<GianoSmartAccountImplementation> | null;
};

export type FeeValues = { maxFeePerGas: bigint; maxPriorityFeePerGas: bigint };

/** Fee precedence: explicit request > bundler-prepared > fallback estimation. */
export function resolveUserOpFees(
	requested: Partial<FeeValues>,
	prepared: Partial<FeeValues>,
	fallback: FeeValues,
): FeeValues {
	return {
		maxFeePerGas:
			requested.maxFeePerGas ?? prepared.maxFeePerGas ?? fallback.maxFeePerGas,
		maxPriorityFeePerGas:
			requested.maxPriorityFeePerGas ??
			prepared.maxPriorityFeePerGas ??
			fallback.maxPriorityFeePerGas,
	};
}

/**
 * The exact bytes that personal_sign and eth_sign sign (EIP-191), and that the consent screen
 * shows. A 0x-prefixed hex message with whole bytes is its raw bytes; any other message, including
 * odd-length hex, is its UTF-8 text. Passing a hex string to signMessage as a plain string would
 * make viem hash the hex characters themselves, so the signature would cover a different payload
 * from the one the dApp sent and the consent screen showed.
 */
export function toPersonalMessageBytes(message: string): Uint8Array {
	return isHex(message) && message.length % 2 === 0
		? hexToBytes(message)
		: stringToBytes(message);
}

/**
 * Seconds before the contract's limit at which the provider renews an authenticated-read
 * signature. It covers the time the passkey prompt takes and a latest block that is a few
 * seconds old.
 */
const STATIC_SIGNATURE_RENEW_MARGIN_SECONDS = 60;

/** The `signedStaticCall` errors that mean the wallet rejected the signature itself. */
const STATIC_SIGNATURE_ERRORS = new Set([
	"StaticCallInvalidSignature",
	"StaticCallSignatureExpired",
	"StaticCallSignatureNotYetValid",
]);

/** True when the wallet rejected an authenticated-read signature, not the read itself. */
const isStaticSignatureRejection = (error: unknown): boolean => {
	if (!(error instanceof BaseError)) return false;
	const revert = error.walk(
		(cause) => cause instanceof ContractFunctionRevertedError,
	);
	return (
		revert instanceof ContractFunctionRevertedError &&
		STATIC_SIGNATURE_ERRORS.has(revert.data?.errorName ?? "")
	);
};

type StaticPermission = {
	signature: Hex;
	signedAt: number;
	/**
	 * Local time (ms) after which the provider signs again. It is measured on the local clock
	 * only, from the moment signing started, so a local clock that differs from the chain's
	 * does not move it.
	 */
	renewAtMs: number;
};

export const createGianoProvider = (
	options: CreateGianoProviderParams,
): {
	readonly gianoClient: PublicClient;
	readonly gianoProvider: GianoProvider;
} => {
	const preference = resolvePasskeyDevicePreference(
		options.passkeyDevicePreference,
	);
	const getFn = passkeyCredentialGet(preference);
	const injection = withValidation(options.injection);
	const { transports, chains, initialChainId, bundlers, factoryAddresses } =
		options;
	const logger = options.logger ?? defaultGianoLogger;
	const estimateFeesPerGas =
		options.estimateFeesPerGas ??
		(async (_chainId: number) => ({
			maxFeePerGas: parseGwei("200"),
			maxPriorityFeePerGas: parseGwei("2"),
		}));

	let smartAccount: SmartAccount<GianoSmartAccountImplementation> | null;
	let chain: Chain | undefined;
	let transport: Transport | undefined;
	let client: PublicClient | undefined;
	// Chain-bound state, swapped as one unit by wallet_switchEthereumChain. Leaving any of it
	// behind on a chain change is the latent defect this fixes: with two chains configured it
	// would silently submit user operations to the PREVIOUS chain's bundler.
	let bundler: BundlerClient | undefined;
	let factoryAddress: Address | undefined;
	// Authenticated-read signatures, one per (account, target, calldata). Each signature covers
	// its own target and calldata, so a cached one can only repeat a read the user approved.
	const staticSignatures = new Map<string, StaticPermission>();
	// Signatures in progress, by the same key, so identical concurrent reads share one prompt.
	const pendingStaticSignatures = new Map<string, Promise<StaticPermission>>();
	// The browser allows one passkey prompt at a time, so signings run one after another.
	let staticSigningQueue: Promise<unknown> = Promise.resolve();
	// Bumped on every clear, so a signing that finishes after a disconnect or chain switch
	// does not write into the new session's cache.
	let staticSignatureGeneration = 0;
	let staticSignatureLifetime = 0n;
	const clearStaticSignatures = () => {
		staticSignatures.clear();
		pendingStaticSignatures.clear();
		staticSignatureGeneration += 1;
	};
	const eventListeners: Partial<EventListeners> = {};

	const submitUserOperation = async (
		userOpRequest: SendUserOperationParameters<
			SmartAccount<GianoSmartAccountImplementation>,
			undefined,
			TransactionRequest[]
		> & {
			account: SmartAccount<GianoSmartAccountImplementation>;
		},
	) => {
		if (injection.submitUserOperation === undefined) {
			return await bundler!.sendUserOperation(userOpRequest);
		}
		// Hook provided: prepare complete user operation, sign it, and use backend validation and submission

		/*
		 * Fees are resolved BEFORE estimating and preparing, not after.
		 *
		 * A validating paymaster signs the operation's gas fees, and viem runs the paymaster hooks
		 * inside `prepareUserOperation`. Resolving fees afterwards would issue an authorisation over
		 * one set of fees and submit the operation with another — which the paymaster rejects on chain
		 * as `AA34`, long after anything could explain why. It also let the paymaster be asked to
		 * authorise an operation whose cost was not yet known, which is not a question it can answer.
		 *
		 * Doing it first is also simply more correct for the unsponsored path: the gas estimate is
		 * computed against the fees the operation will actually carry.
		 */
		const fees = resolveUserOpFees(
			userOpRequest,
			{},
			await estimateFeesPerGas(chain!.id),
		);
		const requestWithFees = { ...userOpRequest, ...fees };

		/*
		 * One `prepareUserOperation`, not an `estimateUserOperationGas` followed by a prepare.
		 *
		 * `prepareUserOperation` estimates gas itself, so the separate estimate was always redundant —
		 * but with a paymaster attached it is actively harmful: each call runs the paymaster hooks, and
		 * viem picks a fresh random nonce key each time. Against a validating paymaster that means two
		 * *signed* authorisations and two balance reservations per transaction, only one of which is
		 * ever submitted. The unused one holds the tenant's funds until its TTL expires, so a tenant's
		 * effective available balance is silently halved.
		 */
		const prepared = await bundler!.prepareUserOperation(requestWithFees);
		if (!prepared) {
			throw new Error("Could not prepare user operation");
		}

		const preparedWithGas: UserOperation<GianoEntryPointVersion> = {
			...prepared,
			// Still applied over `prepared`, because `prepareUserOperation` may echo its own fee values
			// and the authorisation was issued against these.
			...fees,
		};

		// Sign the user operation
		const signature =
			await userOpRequest.account.signUserOperation(preparedWithGas);

		// Create the complete signed user operation
		const signedUserOp = {
			...preparedWithGas,
			sender: await userOpRequest.account.getAddress(),
			signature,
			account: {
				entryPoint: {
					address: GianoEntryPointAddress,
				},
			},
		};

		// The chain the operation was hashed and signed for travels with the submission: the
		// injection is chain-agnostic, and the backend refuses to guess (MC-53).
		return await injection.submitUserOperation(signedUserOp, chain!.id);
	};

	const emit = <E extends keyof EIP1193EventMap>(
		event: E,
		payload: Parameters<EIP1193EventMap[E]>[0],
	) => {
		eventListeners[event]?.forEach((listener) => {
			listener(payload);
		});
	};

	const methods = {
		eth_accounts: async () => {
			return smartAccount ? [await smartAccount.getAddress()] : [];
		},
		giano_restoreAccount: async () => {
			if (smartAccount) {
				return [await smartAccount.getAddress()];
			}
			try {
				const credentialInfo = await injection.getCredentialInfo();
				// Only a single stored credential can be restored silently; anything else
				// (none registered, an explicit user-pick, or an ambiguous list) needs the
				// full sign-in ceremony via eth_requestAccounts.
				const { credentialId } = credentialInfo;
				const rawId =
					credentialId instanceof Array
						? credentialId[0]
						: credentialId === null || credentialId === "user-pick"
							? null
							: credentialId;
				if (!rawId) {
					return [];
				}

				// Rebuild from the stored public key using the persisted wallet-api session.
				// No `navigator.credentials.get` here — the only passkey prompt happens later,
				// when a user operation or message is actually signed.
				const { x, y } = await injection.getPublicKeyByCredentialId(
					rawId as ArrayBuffer,
				);
				if (x === toHex(0, { size: 32 })) {
					// wallet-api has no public key for this credential (or the session is invalid)
					return [];
				}

				smartAccount = await toGianoSmartAccount({
					client: client!,
					owners: [
						toWebAuthnAccount({
							getFn,
							credential: {
								id: toBase64Url(rawId as ArrayBuffer),
								publicKey: concatHex([x, y]),
							},
						}),
					],
					factoryAddress: factoryAddress!,
				});

				const smartAccountAddress = await smartAccount.getAddress();
				emit("connect", { chainId: `0x${chain!.id.toString(16)}` });
				emit("accountsChanged", [smartAccountAddress]);
				return [smartAccountAddress];
			} catch (error) {
				// Best-effort: any failure (expired session, network, unknown credential) just
				// means "not restorable silently" — the caller should fall back to a sign-in.
				logger.warn("giano_restoreAccount: silent restore failed", error);
				smartAccount = null;
				return [];
			}
		},
		eth_chainId: async () => {
			return `0x${chain!.id.toString(16)}`;
		},
		eth_call: async (params) => {
			logger.debug("eth_call", params);

			return client!.request({ method: "eth_call", params });
		},
		signed_eth_call: async (params) => {
			// Check if smartAccount is available before proceeding with authenticated calls
			if (!smartAccount) {
				logger.warn(
					"Smart account not available, falling back to regular call",
				);
				return client!.request({ method: "eth_call", params });
			}

			// The session this read belongs to. A disconnect, a chain switch or a new account
			// ends it, and the read must not sign, cache or send anything after that.
			const account = smartAccount;
			const readClient = client!;
			const generation = staticSignatureGeneration;
			const isCurrent = () =>
				generation === staticSignatureGeneration &&
				smartAccount === account &&
				client === readClient;
			const assertCurrent = () => {
				if (!isCurrent())
					throw new GianoError(
						"signed_eth_call: the session changed during the read; send it again",
					);
			};

			// Check if the account is deployed before attempting authenticated calls
			const isDeployed = await isSmartAccountDeployed(readClient, account);
			// the fallback below sends the read too, so check the session before either path
			assertCurrent();
			if (!isDeployed) {
				logger.warn(
					"Smart account not deployed yet, falling back to regular call",
				);
				return readClient.request({ method: "eth_call", params });
			}

			const [transaction] = params;

			if (!transaction.to) {
				throw new GianoError("signed_eth_call: `transaction.to` is required");
			}
			if (!transaction.data) {
				throw new GianoError("signed_eth_call: `transaction.data` is required");
			}
			const target = transaction.to;
			const data = transaction.data;

			// if the lifetime of the static signature is not known, fetch and cache it
			let lifetime = staticSignatureLifetime;
			if (lifetime === 0n) {
				lifetime = await readClient.readContract({
					address: await account.getAddress(),
					abi: account.abi,
					functionName: "getSignatureLifetime",
				});
				assertCurrent();
				staticSignatureLifetime = lifetime;
			}
			const lifetimeSeconds = Number(lifetime);
			const key = [account.address, target, data]
				.map((part) => part.toLowerCase())
				.join(":");

			const signPermission = (): Promise<StaticPermission> => {
				assertCurrent();
				const pending = pendingStaticSignatures.get(key);
				if (pending) return pending;
				const sign = async (): Promise<StaticPermission> => {
					// a read queued behind another signing must not prompt for an ended session
					assertCurrent();
					const startedAtMs = Date.now();
					// The provider sets signedAt itself, so it can check the session again between
					// the block lookup and the passkey prompt.
					const { timestamp } = await readClient.getBlock();
					assertCurrent();
					const { signature, signedAt } =
						await account.signStaticCallPermission({
							target,
							data,
							signedAt:
								Number(timestamp) - STATIC_CALL_SIGNED_AT_BACKDATE_SECONDS,
						});
					// signedAt is back-dated, so the contract's limit is that much earlier.
					const usableSeconds =
						lifetimeSeconds -
						STATIC_CALL_SIGNED_AT_BACKDATE_SECONDS -
						STATIC_SIGNATURE_RENEW_MARGIN_SECONDS;
					return {
						signature,
						signedAt,
						renewAtMs: startedAtMs + usableSeconds * 1000,
					};
				};
				const signing = staticSigningQueue.then(sign, sign);
				staticSigningQueue = signing.catch(() => undefined);
				const tracked: Promise<StaticPermission> = signing
					.then((permission) => {
						if (isCurrent()) staticSignatures.set(key, permission);
						return permission;
					})
					.finally(() => {
						if (pendingStaticSignatures.get(key) === tracked)
							pendingStaticSignatures.delete(key);
					});
				pendingStaticSignatures.set(key, tracked);
				return tracked;
			};

			const readWith = (permission: StaticPermission) => {
				assertCurrent();
				return readClient.readContract({
					abi: account.abi,
					address: account.address,
					functionName: "signedStaticCall",
					args: [
						{
							target,
							data,
							signedAt: BigInt(permission.signedAt),
							signature: permission.signature,
						},
					],
				});
			};

			// The wallet rejected the signature: for example, the chain's time passed its limit,
			// or the signing owner was removed. Never send it again.
			const removeIfRejected = (
				error: unknown,
				permission: StaticPermission,
			): boolean => {
				if (!isStaticSignatureRejection(error)) return false;
				if (staticSignatures.get(key) === permission)
					staticSignatures.delete(key);
				return true;
			};

			const now = Date.now();
			const cached = staticSignatures.get(key);
			const reused = cached !== undefined && now < cached.renewAtMs;
			if (!reused) {
				for (const [cachedKey, entry] of staticSignatures) {
					if (now >= entry.renewAtMs) staticSignatures.delete(cachedKey);
				}
			}
			const permission = reused ? cached : await signPermission();

			try {
				return await readWith(permission);
			} catch (error) {
				// A new signature that failed would fail the same way if signed again.
				if (!removeIfRejected(error, permission) || !reused) throw error;
			}
			// The cached signature was rejected: sign once more and repeat the read. Another read
			// that used the same signature may have replaced it already; use that one instead.
			const latest = staticSignatures.get(key);
			const replacement =
				latest !== undefined &&
				latest !== permission &&
				Date.now() < latest.renewAtMs
					? latest
					: await signPermission();
			try {
				return await readWith(replacement);
			} catch (error) {
				removeIfRejected(error, replacement);
				throw error;
			}
		},
		wallet_addEthereumChain: async () => {
			// MC-14: an explicit, typed refusal — never a silent no-op that appears to succeed.
			// A chain is a member of the deployment's closed configured list (D8), never a value
			// a caller adds at runtime.
			throw new GianoError(
				"wallet_addEthereumChain is not supported: Giano serves a closed, configured list of chains",
			);
		},
		wallet_revokePermissions: async ([permissions]) => {
			// ignoring permissions, revoking all
			// we only support one connected account per provider instance
			smartAccount = null;
			clearStaticSignatures();
			emit("accountsChanged", []);
			emit("disconnect", {
				code: 4900,
				name: "Disconnected",
				message: "User disconnected",
				details: "User disconnected",
			});

			return null;
		},
		wallet_switchEthereumChain: async ([{ chainId: chainIdHex }]) => {
			const chainId = parseInt(chainIdHex, 16);
			if (chainId === chain?.id) {
				return null;
			}
			const newChain = chains.find((chain) => chain.id === chainId);
			if (!newChain) {
				throw new Error(`Unknown chain: ${chainId}`);
			}
			const newTransport = transports?.[newChain.id];
			if (!newTransport) {
				throw new Error("No transport for chain");
			}
			// Throwing rather than falling back is deliberate: a chain configured for reads but
			// not for submission is a misconfiguration, and silently keeping the previous chain's
			// bundler is exactly the defect this closes (MC-113) — a "switched" provider would
			// keep submitting user operations to the OLD chain's bundler and deriving addresses
			// from the OLD chain's factory.
			const newBundler = bundlers[newChain.id];
			if (!newBundler) {
				throw new Error(`No bundler for chain ${chainId}`);
			}
			const newFactory = factoryAddresses[newChain.id];
			if (!newFactory) {
				throw new Error(`No factory address for chain ${chainId}`);
			}
			smartAccount = null;
			// The cached authenticated-read signature was produced against a specific account on a
			// specific chain, with a lifetime read from that account. Carrying it across a chain
			// change would present a signature from one chain to a contract on another.
			clearStaticSignatures();
			staticSignatureLifetime = 0n;
			chain = newChain;
			transport = newTransport;
			client = createPublicClient({ transport, chain });
			bundler = newBundler;
			factoryAddress = newFactory;

			emit("chainChanged", `0x${chainId.toString(16)}`);
			return null;
		},
		eth_requestAccounts: async () => {
			if (smartAccount) {
				return [await smartAccount.getAddress()];
			}

			const credentialInfo = await injection.getCredentialInfo();

			if (credentialInfo.credentialId !== null) {
				const webAuthnAccount = await getWebAuthnAccount(
					credentialInfo,
					injection,
					preference,
				);
				if (!webAuthnAccount) {
					throw new Error("Invalid credential");
				}
				smartAccount = await toGianoSmartAccount({
					client: client!,
					owners: [webAuthnAccount],
					factoryAddress: factoryAddress!,
				});
				const smartAccountAddress = await smartAccount.getAddress();

				emit("connect", { chainId: `0x${chain!.id.toString(16)}` });
				emit("accountsChanged", [smartAccountAddress]);

				return [smartAccountAddress];
			}

			const credentialName = await injection.getNameForCredential();
			const chainId = `0x${chain!.id.toString(16)}`;
			const residentKey =
				credentialInfo.residentKey ?? DEFAULT_RESIDENT_KEY_REQUIREMENT;
			const userVerification =
				credentialInfo.userVerification ??
				DEFAULT_USER_VERIFICATION_REQUIREMENT;

			const credential = await createWebAuthnCredential({
				createFn: passkeyCredentialCreate(preference),
				user: {
					name: credentialName,
					// The handle deliberately carries NO chain id (MC-78): the credential it names is
					// valid on every chain the deployment serves, and the handle can never be rewritten.
					id: await injection.encodeUserId(
						uuidv4().replace(/-/g, ""),
						factoryAddress!,
						ChainType.EVM,
					),
				},
				challenge: credentialInfo.challenge,
				authenticatorSelection: {
					userVerification,
					residentKey,
					requireResidentKey: residentKey === "required",
				},
			});

			const handlerCreatedAddress = await injection.onCredentialCreated(
				credentialName,
				credentialInfo.challenge,
				credential.raw,
			);

			if (handlerCreatedAddress) {
				smartAccount = await toGianoSmartAccount({
					client: client!,
					owners: [toWebAuthnAccount({ getFn, credential })],
					address: handlerCreatedAddress,
					factoryAddress: factoryAddress!,
				});

				emit("connect", { chainId });
				emit("accountsChanged", [handlerCreatedAddress]);
				return [handlerCreatedAddress];
			}

			smartAccount = await toGianoSmartAccount({
				client: client!,
				owners: [toWebAuthnAccount({ getFn, credential })],
				factoryAddress: factoryAddress!,
			});

			const xyVector = extractXYCoords(credential.publicKey);

			// NOTE: it is needed to deploy the smart account if we want to
			// use it for read calls or to receive funds right away, if not,
			// the account will be deployed on the first actual transaction
			try {
				await ensureSmartAccountIsDeployed(
					smartAccount,
					client!,
					methods.eth_sendTransaction,
				);
			} catch (error) {
				logger.error("Failed to ensure smart account is deployed:", error);
			}

			// Always call the injection callback regardless of deployment status
			await injection.onCredentialKey(credential.raw.rawId, xyVector);

			const smartAccountAddress = await smartAccount.getAddress();

			emit("connect", { chainId: `0x${chain!.id.toString(16)}` });
			emit("accountsChanged", [smartAccountAddress]);
			return [smartAccountAddress];
		},
		eth_sendTransaction: async ([transaction]) => {
			if (!smartAccount) {
				throw new GianoError("Giano not connected");
			}

			if (!transaction.to) {
				throw new GianoError("eth_sendTransaction: `to` field is required");
			}

			const calls: Call[] = [
				{
					to: transaction.to,
					value:
						transaction.value === undefined ? 0n : BigInt(transaction.value),
					data: transaction.data ?? "0x",
				},
			];

			return await submitUserOperation({ calls, account: smartAccount });
		},
		waitForUserOperationReceipt: async ([hash]: [Hash]) => {
			return bundler!.waitForUserOperationReceipt({ hash });
		},
		personal_sign: async ([message, address]: [string, Address]) => {
			if (!smartAccount) {
				throw new Error("Giano not connected");
			}
			const accountAddress = await smartAccount.getAddress();
			if (address.toLowerCase() !== accountAddress.toLowerCase()) {
				throw new Error("Address mismatch");
			}

			return smartAccount.signMessage({
				message: { raw: toPersonalMessageBytes(message) },
			});
		},
		eth_sign: async ([address, message]: [Address, string]) => {
			if (!smartAccount) {
				throw new Error("Giano not connected");
			}
			const accountAddress = await smartAccount.getAddress();
			if (address.toLowerCase() !== accountAddress.toLowerCase()) {
				throw new Error("Address mismatch");
			}

			return smartAccount.signMessage({
				message: { raw: toPersonalMessageBytes(message) },
			});
		},
		eth_signTypedData_v4: async ([address, typedData]: [Address, string]) => {
			logger.debug("eth_signTypedData_v4", { address, typedData });
			if (!smartAccount) {
				throw new Error("Giano not connected");
			}
			const accountAddress = await smartAccount.getAddress();
			if (address.toLowerCase() !== accountAddress.toLowerCase()) {
				throw new Error("Address mismatch");
			}

			// Parse the JSON string if it's a string
			const parsedTypedData =
				typeof typedData === "string" ? JSON.parse(typedData) : typedData;
			return smartAccount.signTypedData(parsedTypedData);
		},
		eth_signUserOperation: async ([userOp]: [any]) => {
			logger.debug("eth_signUserOperation", { userOp });
			// Check and sign with one account instance. A restore or login can replace
			// `smartAccount` during the await below, and the new account would sign as itself.
			const account = smartAccount;
			if (!account) {
				throw new Error("Giano not connected");
			}

			// The signature is only valid on the chain whose id is in the hash. Sign for the
			// connected chain only: a dApp-supplied chainId would produce a signature for a chain
			// the user never chose.
			const { chainId, ...operation } = userOp;
			if (chainId !== undefined && Number(chainId) !== chain?.id) {
				throw new Error("Chain mismatch");
			}
			const sender = await account.getAddress();
			if (
				operation.sender !== undefined &&
				String(operation.sender).toLowerCase() !== sender.toLowerCase()
			) {
				throw new Error("Address mismatch");
			}

			return account.signUserOperation(operation);
		},
		eth_sendSignedUserOperation: async ([signedUserOp]: [
			UserOperation<GianoEntryPointVersion>,
		]) => {
			logger.debug("eth_sendSignedUserOperation", { signedUserOp });
			if (!smartAccount) {
				throw new Error("Giano not connected");
			}

			// Submit the exact operation the caller already signed. Preparing or signing it
			// again changes its paymaster authorisation and breaks the raw three-step flow.
			const sender = await smartAccount.getAddress();
			if (signedUserOp.sender.toLowerCase() !== sender.toLowerCase())
				throw new Error("Address mismatch");
			if (injection.submitUserOperation) {
				return injection.submitUserOperation(
					{
						...signedUserOp,
						account: { entryPoint: { address: GianoEntryPointAddress } },
					} as Parameters<NonNullable<typeof injection.submitUserOperation>>[0],
					chain!.id,
				);
			}
			// viem prepares again when either the request or client supplies an account.
			return sendUserOperation(
				{ ...bundler!, account: undefined },
				{
					...signedUserOp,
					account: undefined,
					entryPointAddress: GianoEntryPointAddress,
				},
			);
		},
		eth_prepareUserOperation: async ([calls, options = {}]) => {
			logger.debug("eth_prepareUserOperation", { calls, options });
			if (!smartAccount) {
				throw new Error("Giano not connected");
			}

			const op = {
				calls,
				...options,
			};

			const fees = resolveUserOpFees(
				options,
				{},
				await estimateFeesPerGas(chain!.id),
			);
			const prepared = await bundler!.prepareUserOperation({
				account: smartAccount,
				...op,
				...fees,
			});

			// viem echoes its account object, including signing functions. Only the
			// operation can cross the popup's postMessage boundary.
			const { account: _account, ...operation } = prepared;
			return {
				...operation,
				preVerificationGas: prepared.preVerificationGas,
				...fees,
			};
		},
	} satisfies GianoProviderMethodsMap;

	methods.wallet_switchEthereumChain([
		{ chainId: initialChainId.toString(16) },
	]);

	const provider: GianoProvider = {
		getSmartAccount: () => smartAccount,
		request: (async (args: EIP1193Parameters) => {
			const { method, params } = args;

			if (!(method in methods)) {
				return client!.request({ ...args } as any);
			}
			try {
				const handler = (
					methods as Record<string, (params: unknown) => Promise<unknown>>
				)[method];
				const response = await handler(params);
				return response;
			} catch (e) {
				logger.error("provider request failed", e);
				throw e;
			}
		}) as GianoProvider["request"],
		on: <E extends keyof EIP1193EventMap>(
			event: E,
			listener: EventHandler<E>,
		) => {
			if (!eventListeners[event]) {
				eventListeners[event] = new Set();
			}
			eventListeners[event]!.add(listener);
			return provider;
		},
		removeListener: <E extends keyof EIP1193EventMap>(
			event: E,
			listener: EventHandler<E>,
		) => {
			eventListeners[event]?.delete(listener);
			return provider;
		},
	};

	return <const>{
		gianoClient: client!,
		gianoProvider: provider,
	};
};
