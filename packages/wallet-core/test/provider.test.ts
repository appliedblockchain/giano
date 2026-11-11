import { gianoSmartWalletAbi } from "@appliedblockchain/giano-contracts";
import {
	type Address,
	concatHex,
	custom,
	decodeFunctionData,
	encodeErrorResult,
	type Hex,
	hashMessage,
	isAddressEqual,
	parseGwei,
	type SignableMessage,
	stringToBytes,
	toHex,
} from "viem";
import {
	createBundlerClient,
	entryPoint09Address,
} from "viem/account-abstraction";
import {
	afterEach,
	beforeEach,
	describe,
	expect,
	it,
	type MockInstance,
	vi,
} from "vitest";
import { GianoAccountOwnerError } from "../src/account";
import {
	ChainType,
	type CreateGianoProviderParams,
	createGianoProvider,
	type GianoProvider,
	isChainType,
	resolveUserOpFees,
	toPersonalMessageBytes,
} from "../src/provider";
import {
	createMockBundler,
	createMockInjection,
	createMockTransport,
	FACTORY_ADDRESS,
	type MockClientOptions,
	TEST_CHAIN_ID,
	testChain,
	WALLET_ADDRESS,
} from "./helpers";
import {
	type InstalledWebAuthnMock,
	installWebAuthnMock,
	type MockAuthenticator,
} from "./webauthn-mock";

let mock: InstalledWebAuthnMock;
beforeEach(() => (mock = installWebAuthnMock()));
afterEach(() => mock.uninstall());

type BuildOptions = {
	transportOptions?: MockClientOptions;
	injection?: CreateGianoProviderParams["injection"];
	bundler?: CreateGianoProviderParams["bundlers"][number];
	overrides?: Partial<CreateGianoProviderParams>;
};

const silentLogger = { debug: () => {}, warn: () => {}, error: () => {} };

function buildProvider(
	authenticator: MockAuthenticator,
	opts: BuildOptions = {},
) {
	const { transport } = createMockTransport({
		code: "0xabcd",
		...opts.transportOptions,
	});
	const { bundler, sentUserOps } = createMockBundler();
	const provider = createGianoProvider({
		initialChainId: TEST_CHAIN_ID,
		bundlers: { [TEST_CHAIN_ID]: opts.bundler ?? bundler },
		chains: [testChain],
		transports: { [TEST_CHAIN_ID]: transport },
		injection: opts.injection ?? createMockInjection(authenticator),
		factoryAddresses: { [TEST_CHAIN_ID]: FACTORY_ADDRESS },
		logger: silentLogger,
		...opts.overrides,
	}).gianoProvider;
	return { provider, sentUserOps };
}

/**
 * Counts passkey assertions from now on, and the highest number that run at the same time.
 * Each authenticated-read signature is one assertion.
 */
function countPasskeyPrompts(
	authenticator: MockAuthenticator,
	/** Runs inside each prompt, before the authenticator answers. */
	duringPrompt?: () => Promise<void>,
) {
	const original = authenticator.get.bind(authenticator);
	let count = 0;
	let active = 0;
	let maxActive = 0;
	vi.spyOn(authenticator, "get").mockImplementation(async (options) => {
		count += 1;
		active += 1;
		maxActive = Math.max(maxActive, active);
		try {
			await duringPrompt?.();
			return await original(options);
		} finally {
			active -= 1;
		}
	});
	return {
		get count() {
			return count;
		},
		get maxActive() {
			return maxActive;
		},
	};
}

/** Registers a fresh passkey (create path) and connects. */
async function connect(provider: GianoProvider): Promise<string> {
	const [address] = await provider.request({ method: "eth_requestAccounts" });
	return address;
}

describe("pure helpers", () => {
	it("toPersonalMessageBytes reads whole-byte hex as raw bytes and anything else as text", () => {
		expect(toPersonalMessageBytes(toHex("hi"))).toEqual(stringToBytes("hi"));
		expect(toPersonalMessageBytes("0xdeadbeef")).toEqual(
			new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
		);
		expect(toPersonalMessageBytes("hello")).toEqual(stringToBytes("hello"));
		// Not valid hex, or not whole bytes: signed as the text the dApp sent, never re-padded.
		expect(toPersonalMessageBytes("0xhello")).toEqual(stringToBytes("0xhello"));
		expect(toPersonalMessageBytes("0x123")).toEqual(stringToBytes("0x123"));
		expect(hashMessage({ raw: toPersonalMessageBytes("hi") })).toBe(
			hashMessage("hi"),
		);
	});

	it("resolveUserOpFees follows request > prepared > fallback precedence", () => {
		const fallback = { maxFeePerGas: 9n, maxPriorityFeePerGas: 8n };
		expect(
			resolveUserOpFees(
				{ maxFeePerGas: 1n, maxPriorityFeePerGas: 2n },
				{},
				fallback,
			),
		).toEqual({ maxFeePerGas: 1n, maxPriorityFeePerGas: 2n });
		expect(
			resolveUserOpFees(
				{},
				{ maxFeePerGas: 3n, maxPriorityFeePerGas: 4n },
				fallback,
			),
		).toEqual({ maxFeePerGas: 3n, maxPriorityFeePerGas: 4n });
		expect(resolveUserOpFees({}, {}, fallback)).toEqual(fallback);
		expect(
			resolveUserOpFees(
				{ maxFeePerGas: 0n, maxPriorityFeePerGas: 0n },
				{ maxFeePerGas: 3n, maxPriorityFeePerGas: 4n },
				fallback,
			),
		).toEqual({ maxFeePerGas: 0n, maxPriorityFeePerGas: 0n });
		expect(
			resolveUserOpFees(
				{},
				{ maxFeePerGas: 0n, maxPriorityFeePerGas: 0n },
				fallback,
			),
		).toEqual({ maxFeePerGas: 0n, maxPriorityFeePerGas: 0n });
		expect(
			resolveUserOpFees(
				{ maxPriorityFeePerGas: 0n },
				{ maxFeePerGas: 3n },
				fallback,
			),
		).toEqual({ maxFeePerGas: 3n, maxPriorityFeePerGas: 0n });
	});

	it("isChainType / ChainType", () => {
		expect(isChainType(0)).toBe(true);
		expect(isChainType(ChainType.EVM)).toBe(true);
		expect(isChainType(99)).toBe(false);
		expect(isChainType("0")).toBe(false);
		expect(ChainType.HARDHAT).toBe(ChainType.EVM);
	});
});

describe("connection", () => {
	it("registers a passkey and reports the smart-account address (create path)", async () => {
		const { provider } = buildProvider(mock.authenticator);
		const events: Record<string, unknown[]> = {
			connect: [],
			accountsChanged: [],
		};
		provider.on("connect", (p) => events.connect.push(p));
		provider.on("accountsChanged", (p) => events.accountsChanged.push(p));

		const address = await connect(provider);
		expect(address.toLowerCase()).toBe(WALLET_ADDRESS.toLowerCase());
		expect(events.connect).toHaveLength(1);
		expect(events.accountsChanged[0]).toEqual([address]);
		expect(provider.getSmartAccount()).not.toBeNull();
	});

	it("honours an address returned by onCredentialCreated (handler-managed deployment)", async () => {
		const handlerAddress =
			"0x000000000000000000000000000000000000cafe" as `0x${string}`;
		const injection = createMockInjection(mock.authenticator, {
			onCredentialCreated: async () => handlerAddress,
		});
		const { provider } = buildProvider(mock.authenticator, { injection });
		const [address] = await provider.request({ method: "eth_requestAccounts" });
		expect(address).toBe(handlerAddress);
	});

	it("signs in with an existing resident credential (sign-in path)", async () => {
		// Pre-register a passkey so a resident credential exists to select.
		const created = await mock.authenticator.create({
			publicKey: {
				rp: { id: "localhost", name: "g" },
				user: { id: new Uint8Array([1]), name: "a", displayName: "a" },
				challenge: new Uint8Array([1]),
				pubKeyCredParams: [{ type: "public-key", alg: -7 }],
			},
		} as CredentialCreationOptions);
		const injection = createMockInjection(mock.authenticator, {
			credentialId: new Uint8Array(created.rawId),
		});
		const { provider } = buildProvider(mock.authenticator, { injection });

		const [address] = await provider.request({ method: "eth_requestAccounts" });
		expect(address.toLowerCase()).toBe(WALLET_ADDRESS.toLowerCase());
	});

	it("returns the cached account on a second eth_requestAccounts and via eth_accounts", async () => {
		const { provider } = buildProvider(mock.authenticator);
		expect(await provider.request({ method: "eth_accounts" })).toEqual([]);
		const address = await connect(provider);
		expect(await provider.request({ method: "eth_requestAccounts" })).toEqual([
			address,
		]);
		expect(await provider.request({ method: "eth_accounts" })).toEqual([
			address,
		]);
	});

	it("deploys a counterfactual account when not yet on-chain", async () => {
		// getCode: undeployed on the ensure-check, deployed thereafter.
		const injection = createMockInjection(mock.authenticator);
		const { provider, sentUserOps } = buildProvider(mock.authenticator, {
			injection,
			transportOptions: { code: (i) => (i === 0 ? "0x" : "0xabcd") },
		});
		await connect(provider);
		expect(sentUserOps.length).toBe(1); // deployment user op was sent
	});
});

describe("silent account restore (giano_restoreAccount)", () => {
	/** Pre-registers a resident passkey and returns its rawId for a sign-in/restore injection. */
	async function registerCredential(): Promise<Uint8Array<ArrayBuffer>> {
		const created = await mock.authenticator.create({
			publicKey: {
				rp: { id: "localhost", name: "g" },
				user: { id: new Uint8Array([1]), name: "a", displayName: "a" },
				challenge: new Uint8Array([1]),
				pubKeyCredParams: [{ type: "public-key", alg: -7 }],
			},
		} as CredentialCreationOptions);
		return new Uint8Array(created.rawId);
	}

	it("rebuilds the account from a stored credential without a passkey ceremony", async () => {
		const credentialId = await registerCredential();
		const onCredentialSignedIn = vi.fn(async () => true);
		const injection = createMockInjection(mock.authenticator, {
			credentialId,
			onCredentialSignedIn,
		});
		const { provider } = buildProvider(mock.authenticator, { injection });

		const accountsChanged: unknown[] = [];
		provider.on("accountsChanged", (p) => accountsChanged.push(p));

		const [address] = await provider.request({
			method: "giano_restoreAccount",
			params: [],
		});
		expect(address.toLowerCase()).toBe(WALLET_ADDRESS.toLowerCase());
		// No sign-in ceremony was run — the account came from the stored public key only.
		expect(onCredentialSignedIn).not.toHaveBeenCalled();
		expect(provider.getSmartAccount()).not.toBeNull();
		expect(accountsChanged).toEqual([[address]]);
	});

	it('lets a restored account send a transaction (no "not connected")', async () => {
		const credentialId = await registerCredential();
		const injection = createMockInjection(mock.authenticator, { credentialId });
		const { provider, sentUserOps } = buildProvider(mock.authenticator, {
			injection,
		});

		await provider.request({ method: "giano_restoreAccount", params: [] });
		const hash = await provider.request({
			method: "eth_sendTransaction",
			params: [{ to: WALLET_ADDRESS, value: "0x0", data: "0x" }] as never,
		});
		expect(hash).toMatch(/^0x/);
		expect(sentUserOps.length).toBeGreaterThan(0);
	});

	it("returns [] when no credential is registered for the user", async () => {
		const { provider } = buildProvider(mock.authenticator); // default injection: credentialId = null
		expect(
			await provider.request({ method: "giano_restoreAccount", params: [] }),
		).toEqual([]);
		expect(provider.getSmartAccount()).toBeNull();
	});

	it("returns [] and stays disconnected when the persisted session is invalid", async () => {
		const credentialId = await registerCredential();
		const injection = createMockInjection(mock.authenticator, {
			credentialId,
			getPublicKeyByCredentialId: async () => {
				throw new Error("wallet-api /public-key failed: 401");
			},
		});
		const { provider } = buildProvider(mock.authenticator, { injection });

		expect(
			await provider.request({ method: "giano_restoreAccount", params: [] }),
		).toEqual([]);
		expect(provider.getSmartAccount()).toBeNull();
	});

	it("is idempotent — returns the cached address once connected", async () => {
		const { provider } = buildProvider(mock.authenticator);
		const address = await connect(provider);
		expect(
			await provider.request({ method: "giano_restoreAccount", params: [] }),
		).toEqual([address]);
	});
});

describe("explicit smart account address (secondary owner)", () => {
	// The shared account. A passkey added with addOwnerPublicKey was never in its factory salt,
	// so the address derived from that passkey (WALLET_ADDRESS in the mock) is a different account.
	const SHARED_ADDRESS =
		"0x0000000000000000000000000000000000005a5a" as Address;

	/** Registers a resident passkey; returns its id and its owner bytes (x || y). */
	async function registerCredential() {
		const created = await mock.authenticator.create({
			publicKey: {
				rp: { id: "localhost", name: "g" },
				user: { id: new Uint8Array([1]), name: "a", displayName: "a" },
				challenge: new Uint8Array([1]),
				pubKeyCredParams: [{ type: "public-key", alg: -7 }],
			},
		} as CredentialCreationOptions);
		const { x, y } = mock.authenticator.getPublicKeyXY(created.rawId);
		return {
			credentialId: new Uint8Array(created.rawId),
			ownerBytes: concatHex([x, y]),
		};
	}

	/** An injection whose credential info names `address` as the account to connect to. */
	function injectionWithAddress(
		credentialId: Uint8Array<ArrayBuffer> | null,
		address: Address,
		overrides: Parameters<typeof createMockInjection>[1] = {},
	) {
		const base = createMockInjection(mock.authenticator, {
			credentialId,
			...overrides,
		});
		return {
			...base,
			getCredentialInfo: async () => ({
				...(await base.getCredentialInfo()),
				address,
			}),
		} as CreateGianoProviderParams["injection"];
	}

	/** An `isOwnerBytes` answer: only `ownerBytes` owns the shared account. */
	const ownsSharedAccount = (ownerBytes: Hex) =>
		vi.fn(
			(wallet: Address, bytes: Hex) =>
				isAddressEqual(wallet, SHARED_ADDRESS) &&
				bytes.toLowerCase() === ownerBytes.toLowerCase(),
		);

	it("connects a secondary owner to the shared account, not to its derived address", async () => {
		const { credentialId, ownerBytes } = await registerCredential();
		const isOwner = ownsSharedAccount(ownerBytes);
		const { provider } = buildProvider(mock.authenticator, {
			injection: injectionWithAddress(credentialId, SHARED_ADDRESS),
			transportOptions: { isOwner },
		});
		const accountsChanged: unknown[] = [];
		provider.on("accountsChanged", (p) => accountsChanged.push(p));

		const accounts = await provider.request({ method: "eth_requestAccounts" });

		expect(accounts).toEqual([SHARED_ADDRESS]);
		expect(accountsChanged).toEqual([[SHARED_ADDRESS]]);
		expect(await provider.getSmartAccount()?.getAddress()).toBe(SHARED_ADDRESS);
		expect(isOwner).toHaveBeenCalledOnce();
	});

	it("restores a secondary owner's session onto the shared account", async () => {
		const { credentialId, ownerBytes } = await registerCredential();
		const { provider } = buildProvider(mock.authenticator, {
			injection: injectionWithAddress(credentialId, SHARED_ADDRESS),
			transportOptions: { isOwner: ownsSharedAccount(ownerBytes) },
		});

		expect(
			await provider.request({ method: "giano_restoreAccount", params: [] }),
		).toEqual([SHARED_ADDRESS]);
	});

	it("sends a secondary owner's transactions from the shared account", async () => {
		const { credentialId, ownerBytes } = await registerCredential();
		const submitUserOperation = vi.fn(
			async (_op: { sender: Address }, _chainId: number) =>
				`0x${"ab".repeat(32)}` as Hex,
		);
		const { provider } = buildProvider(mock.authenticator, {
			injection: injectionWithAddress(credentialId, SHARED_ADDRESS, {
				submitUserOperation: submitUserOperation as never,
			}),
			transportOptions: { isOwner: ownsSharedAccount(ownerBytes) },
		});
		await provider.request({ method: "eth_requestAccounts" });

		await provider.request({
			method: "eth_sendTransaction",
			params: [
				{ to: "0x1111111111111111111111111111111111111111", value: "0x0" },
			] as never,
		});

		expect(submitUserOperation).toHaveBeenCalledOnce();
		expect(submitUserOperation.mock.calls[0][0].sender).toBe(SHARED_ADDRESS);
	});

	it("refuses a passkey that does not own the requested account", async () => {
		const { credentialId } = await registerCredential();
		const { provider } = buildProvider(mock.authenticator, {
			injection: injectionWithAddress(credentialId, SHARED_ADDRESS),
			transportOptions: { isOwner: () => false },
		});

		await expect(
			provider.request({ method: "eth_requestAccounts" }),
		).rejects.toThrow(GianoAccountOwnerError);
		expect(provider.getSmartAccount()).toBeNull();
		expect(await provider.request({ method: "eth_accounts" })).toEqual([]);
	});

	it("reports a non-owner on silent restore instead of returning []", async () => {
		const { credentialId } = await registerCredential();
		const { provider } = buildProvider(mock.authenticator, {
			injection: injectionWithAddress(credentialId, SHARED_ADDRESS),
			transportOptions: { isOwner: () => false },
		});

		await expect(
			provider.request({ method: "giano_restoreAccount", params: [] }),
		).rejects.toThrow(/not an owner of the smart account/);
		expect(provider.getSmartAccount()).toBeNull();
	});

	it("refuses an undeployed address that is not the passkey's own account", async () => {
		const { credentialId, ownerBytes } = await registerCredential();
		const isOwner = ownsSharedAccount(ownerBytes);
		const { provider } = buildProvider(mock.authenticator, {
			injection: injectionWithAddress(credentialId, SHARED_ADDRESS),
			transportOptions: { code: "0x", isOwner },
		});

		await expect(
			provider.request({ method: "eth_requestAccounts" }),
		).rejects.toThrow(/is not deployed/);
		// An undeployed account has no owners to ask about.
		expect(isOwner).not.toHaveBeenCalled();
		expect(provider.getSmartAccount()).toBeNull();
	});

	it("accepts the passkey's own address before its account is deployed", async () => {
		const { credentialId } = await registerCredential();
		const { provider } = buildProvider(mock.authenticator, {
			injection: injectionWithAddress(credentialId, WALLET_ADDRESS),
			transportOptions: { code: "0x" },
		});

		expect(await provider.request({ method: "eth_requestAccounts" })).toEqual([
			WALLET_ADDRESS,
		]);
	});

	it("keeps the derived address, with no ownership check, when no address is given", async () => {
		const { credentialId } = await registerCredential();
		const isOwner = vi.fn(() => false);
		const { provider } = buildProvider(mock.authenticator, {
			injection: createMockInjection(mock.authenticator, { credentialId }),
			transportOptions: { isOwner },
		});

		const [address] = await provider.request({ method: "eth_requestAccounts" });

		expect(address.toLowerCase()).toBe(WALLET_ADDRESS.toLowerCase());
		expect(isOwner).not.toHaveBeenCalled();
	});

	it("refuses an address for a credential that is being created, before the passkey prompt", async () => {
		const create = vi.spyOn(mock.authenticator, "create");
		const onCredentialCreated = vi.fn(async () => null);
		const { provider } = buildProvider(mock.authenticator, {
			injection: injectionWithAddress(null, SHARED_ADDRESS, {
				onCredentialCreated,
			}),
		});

		await expect(
			provider.request({ method: "eth_requestAccounts" }),
		).rejects.toThrow(/applies only to an existing credential/);
		expect(create).not.toHaveBeenCalled();
		expect(onCredentialCreated).not.toHaveBeenCalled();
	});
});

describe("chain management", () => {
	it("eth_chainId reflects the active chain", async () => {
		const { provider } = buildProvider(mock.authenticator);
		expect(await provider.request({ method: "eth_chainId" })).toBe(
			`0x${TEST_CHAIN_ID.toString(16)}`,
		);
	});

	it("wallet_switchEthereumChain: no-op on same chain, errors on unknown or transport-less chains", async () => {
		const { provider } = buildProvider(mock.authenticator);
		expect(
			await provider.request({
				method: "wallet_switchEthereumChain",
				params: [{ chainId: `0x${TEST_CHAIN_ID.toString(16)}` }],
			}),
		).toBeNull();
		await expect(
			provider.request({
				method: "wallet_switchEthereumChain",
				params: [{ chainId: "0x270f" }],
			}),
		).rejects.toThrow(/Unknown chain/);
	});

	it("wallet_switchEthereumChain errors when the target chain has no transport", async () => {
		const { transport } = createMockTransport({ code: "0xabcd" });
		const otherChain = { ...testChain, id: 999 };
		const { bundler } = createMockBundler();
		const provider = createGianoProvider({
			initialChainId: TEST_CHAIN_ID,
			bundlers: { [TEST_CHAIN_ID]: bundler },
			chains: [testChain, otherChain],
			transports: { [TEST_CHAIN_ID]: transport }, // no transport for 999
			injection: createMockInjection(mock.authenticator),
			factoryAddresses: { [TEST_CHAIN_ID]: FACTORY_ADDRESS },
		}).gianoProvider;
		await expect(
			provider.request({
				method: "wallet_switchEthereumChain",
				params: [{ chainId: "0x3e7" }],
			}),
		).rejects.toThrow(/No transport/);
	});

	it("wallet_switchEthereumChain errors when the target chain has no bundler or no factory", async () => {
		const { transport } = createMockTransport({ code: "0xabcd" });
		const otherChain = { ...testChain, id: 999 };
		const { bundler } = createMockBundler();
		// A chain configured for reads but not for submission is a misconfiguration — silently
		// keeping the previous chain's bundler is exactly the defect §7.3 closes.
		const provider = createGianoProvider({
			initialChainId: TEST_CHAIN_ID,
			bundlers: { [TEST_CHAIN_ID]: bundler },
			chains: [testChain, otherChain],
			transports: { [TEST_CHAIN_ID]: transport, 999: transport },
			injection: createMockInjection(mock.authenticator),
			factoryAddresses: { [TEST_CHAIN_ID]: FACTORY_ADDRESS },
		}).gianoProvider;
		await expect(
			provider.request({
				method: "wallet_switchEthereumChain",
				params: [{ chainId: "0x3e7" }],
			}),
		).rejects.toThrow(/No bundler/);
	});

	it("a chain change swaps the bundler — operations reach the NEW chain's bundler (MC-113)", async () => {
		const chainB = { ...testChain, id: 31338, name: "giano-test-b" };
		const { transport: transportA } = createMockTransport({ code: "0xabcd" });
		const { transport: transportB } = createMockTransport({ code: "0xabcd" });
		const { bundler: bundlerA, sentUserOps: sentA } = createMockBundler();
		const { bundler: bundlerB, sentUserOps: sentB } = createMockBundler();
		const credentialId = await (async () => {
			const created = await mock.authenticator.create({
				publicKey: {
					rp: { id: "localhost", name: "g" },
					user: { id: new Uint8Array([1]), name: "a", displayName: "a" },
					challenge: new Uint8Array([1]),
					pubKeyCredParams: [{ type: "public-key", alg: -7 }],
				},
			} as CredentialCreationOptions);
			return new Uint8Array(created.rawId);
		})();
		const provider = createGianoProvider({
			initialChainId: TEST_CHAIN_ID,
			bundlers: { [TEST_CHAIN_ID]: bundlerA, 31338: bundlerB },
			chains: [testChain, chainB],
			transports: { [TEST_CHAIN_ID]: transportA, 31338: transportB },
			injection: createMockInjection(mock.authenticator, { credentialId }),
			factoryAddresses: {
				[TEST_CHAIN_ID]: FACTORY_ADDRESS,
				31338: FACTORY_ADDRESS,
			},
			logger: silentLogger,
		}).gianoProvider;

		await provider.request({ method: "eth_requestAccounts" });
		await provider.request({
			method: "eth_sendTransaction",
			params: [{ to: WALLET_ADDRESS, value: "0x0", data: "0x" }] as never,
		});
		expect(sentA.length).toBe(1);
		expect(sentB.length).toBe(0);

		await provider.request({
			method: "wallet_switchEthereumChain",
			params: [{ chainId: "0x7a6a" }],
		});
		expect(await provider.request({ method: "eth_chainId" })).toBe("0x7a6a");
		// the chain change nulled the account; reconnect on the new chain
		await provider.request({ method: "eth_requestAccounts" });
		await provider.request({
			method: "eth_sendTransaction",
			params: [{ to: WALLET_ADDRESS, value: "0x0", data: "0x" }] as never,
		});
		expect(sentA.length).toBe(1); // unchanged — nothing leaked to the old chain's bundler
		expect(sentB.length).toBe(1);
	});

	it("wallet_addEthereumChain is refused explicitly, and wallet_revokePermissions disconnects", async () => {
		const { provider } = buildProvider(mock.authenticator);
		await connect(provider);
		await expect(
			provider.request({
				method: "wallet_addEthereumChain",
				params: [{ chainId: "0x1" } as never],
			}),
		).rejects.toThrow(/not supported/);

		const disconnects: unknown[] = [];
		provider.on("disconnect", (p) => disconnects.push(p));
		expect(
			await provider.request({
				method: "wallet_revokePermissions",
				params: [{}] as never,
			}),
		).toBeNull();
		expect(provider.getSmartAccount()).toBeNull();
		expect(disconnects).toHaveLength(1);
	});
});

describe("transactions & user operations", () => {
	it("eth_sendTransaction relays a user op through the bundler", async () => {
		const { provider, sentUserOps } = buildProvider(mock.authenticator);
		await connect(provider);
		const hash = await provider.request({
			method: "eth_sendTransaction",
			params: [
				{
					to: "0x1111111111111111111111111111111111111111",
					value: "0x1",
					data: "0x",
				},
			] as never,
		});
		expect(hash).toMatch(/^0x/);
		expect(sentUserOps.length).toBeGreaterThan(0);
	});

	it("eth_sendTransaction requires a connection and a `to`", async () => {
		const { provider } = buildProvider(mock.authenticator);
		await expect(
			provider.request({
				method: "eth_sendTransaction",
				params: [{ to: "0x1111111111111111111111111111111111111111" }] as never,
			}),
		).rejects.toThrow(/not connected/);
		await connect(provider);
		await expect(
			provider.request({
				method: "eth_sendTransaction",
				params: [{} as never],
			}),
		).rejects.toThrow(/`to` field is required/);
	});

	it("routes through injection.submitUserOperation when provided", async () => {
		const submitUserOperation = vi.fn(
			async () => `0x${"ab".repeat(32)}` as `0x${string}`,
		);
		const injection = createMockInjection(mock.authenticator, {
			submitUserOperation,
		});
		const { provider } = buildProvider(mock.authenticator, { injection });
		await connect(provider);
		const hash = await provider.request({
			method: "eth_sendTransaction",
			params: [
				{
					to: "0x1111111111111111111111111111111111111111",
					value: "0x0",
					data: "0x",
				},
			] as never,
		});
		expect(submitUserOperation).toHaveBeenCalledOnce();
		expect(hash).toBe(`0x${"ab".repeat(32)}`);
	});

	it("eth_prepareUserOperation returns a prepared op with resolved fees", async () => {
		const { provider } = buildProvider(mock.authenticator);
		await connect(provider);
		const op = await provider.request({
			method: "eth_prepareUserOperation",
			params: [
				[
					{
						to: "0x1111111111111111111111111111111111111111",
						value: 0n,
						data: "0x",
					},
				],
			] as never,
		});
		expect(op).toMatchObject({ sender: expect.any(String) });
		expect(op).not.toHaveProperty("account");
		expect(() => structuredClone(op)).not.toThrow();
	});

	it("eth_signUserOperation and eth_sendSignedUserOperation", async () => {
		const { provider } = buildProvider(mock.authenticator);
		await connect(provider);
		const prepared = await provider.request({
			method: "eth_prepareUserOperation",
			params: [
				[
					{
						to: "0x1111111111111111111111111111111111111111",
						value: 0n,
						data: "0x",
					},
				],
			] as never,
		});
		const signature = await provider.request({
			method: "eth_signUserOperation",
			params: [prepared] as never,
		});
		expect(signature).toMatch(/^0x/);
		const hash = await provider.request({
			method: "eth_sendSignedUserOperation",
			params: [{ ...prepared, signature }] as never,
		});
		expect(hash).toMatch(/^0x/);
	});

	it("eth_signUserOperation signs only for the connected chain and account", async () => {
		const { provider } = buildProvider(mock.authenticator);
		await connect(provider);
		const prepared = (await provider.request({
			method: "eth_prepareUserOperation",
			params: [
				[
					{
						to: "0x1111111111111111111111111111111111111111",
						value: 0n,
						data: "0x",
					},
				],
			] as never,
		})) as Record<string, unknown>;
		const { chainId: _ignored, ...operation } = prepared;

		await expect(
			provider.request({
				method: "eth_signUserOperation",
				params: [{ ...operation, chainId: TEST_CHAIN_ID }] as never,
			}),
		).resolves.toMatch(/^0x/);
		await expect(
			provider.request({
				method: "eth_signUserOperation",
				params: [
					{ ...operation, chainId: `0x${TEST_CHAIN_ID.toString(16)}` },
				] as never,
			}),
		).resolves.toMatch(/^0x/);

		await expect(
			provider.request({
				method: "eth_signUserOperation",
				params: [{ ...operation, chainId: TEST_CHAIN_ID + 1 }] as never,
			}),
		).rejects.toThrow("Chain mismatch");
		await expect(
			provider.request({
				method: "eth_signUserOperation",
				params: [
					{
						...operation,
						sender: "0x1111111111111111111111111111111111111111",
					},
				] as never,
			}),
		).rejects.toThrow("Address mismatch");
	});

	it("eth_signUserOperation signs with the account it checked when the account changes during the check", async () => {
		const { provider } = buildProvider(mock.authenticator);
		await connect(provider);
		const prepared = await provider.request({
			method: "eth_prepareUserOperation",
			params: [[{ to: WALLET_ADDRESS, value: 0n, data: "0x" }]] as never,
		});
		const checked = provider.getSmartAccount();
		if (!checked) throw new Error("not connected");
		const getAddress = checked.getAddress.bind(checked);
		const sign = vi.spyOn(checked, "signUserOperation");
		// The account goes away while the provider awaits the checked address.
		vi.spyOn(checked, "getAddress").mockImplementationOnce(async () => {
			await provider.request({
				method: "wallet_revokePermissions",
				params: [{ eth_accounts: {} }],
			} as never);
			return getAddress();
		});

		const signature = await provider.request({
			method: "eth_signUserOperation",
			params: [prepared] as never,
		});
		expect(provider.getSmartAccount()).toBeNull();
		expect(sign).toHaveBeenCalledOnce();
		expect(signature).toMatch(/^0x/);
	});

	it("submits a raw signed operation unchanged without preparing or signing again", async () => {
		const { bundler } = createMockBundler();
		// prepareUserOperation is generic over its request, which vi.spyOn's typing collapses to never.
		const prepare = vi.spyOn(
			bundler,
			"prepareUserOperation",
		) as unknown as MockInstance;
		const submitUserOperation = vi.fn(
			async () => `0x${"ab".repeat(32)}` as `0x${string}`,
		);
		const { provider } = buildProvider(mock.authenticator, {
			bundler,
			injection: createMockInjection(mock.authenticator, {
				submitUserOperation,
			}),
		});
		await connect(provider);
		const prepared = await provider.request({
			method: "eth_prepareUserOperation",
			params: [[{ to: WALLET_ADDRESS, value: 0n, data: "0x" }]] as never,
		});
		const signature = await provider.request({
			method: "eth_signUserOperation",
			params: [prepared] as never,
		});
		const signed = { ...prepared, signature };
		prepare.mockClear();
		await provider.request({
			method: "eth_sendSignedUserOperation",
			params: [signed] as never,
		});
		expect(prepare).not.toHaveBeenCalled();
		expect(submitUserOperation).toHaveBeenCalledWith(
			expect.objectContaining(signed),
			TEST_CHAIN_ID,
		);
		await expect(
			provider.request({
				method: "eth_sendSignedUserOperation",
				params: [
					{ ...signed, sender: "0x1111111111111111111111111111111111111111" },
				] as never,
			}),
		).rejects.toThrow("Address mismatch");
		expect(submitUserOperation).toHaveBeenCalledOnce();
	});

	it("uses the real viem action without account hooks or paymaster refresh for signed operations", async () => {
		const request = vi.fn(async ({ method }: { method: string }) => {
			if (method !== "eth_sendUserOperation")
				throw new Error(`unexpected RPC: ${method}`);
			return `0x${"ab".repeat(32)}`;
		});
		const bundler = createBundlerClient({
			chain: testChain,
			transport: custom({ request }, { retryCount: 0 }),
		});
		// prepareUserOperation is generic over its request, which vi.spyOn's typing collapses to never.
		const prepare = vi.spyOn(
			bundler,
			"prepareUserOperation",
		) as unknown as MockInstance;
		const { provider } = buildProvider(mock.authenticator, { bundler });
		const sender = await connect(provider);
		const account = provider.getSmartAccount()!;
		const sign = vi.spyOn(account, "signUserOperation");
		// Defend against an account attached to either the injected client or caller's payload.
		Object.assign(bundler, { account });
		const signed = {
			sender,
			nonce: 7n,
			callData: "0xabcd",
			callGasLimit: 100_000n,
			verificationGasLimit: 900_000n,
			preVerificationGas: 50_000n,
			maxFeePerGas: 9n,
			maxPriorityFeePerGas: 2n,
			signature: "0x1234",
			paymaster: "0x1111111111111111111111111111111111111111",
			paymasterVerificationGasLimit: 30_000n,
			paymasterPostOpGasLimit: 20_000n,
			paymasterData: "0x5678",
			account,
		};
		await expect(
			provider.request({
				method: "eth_sendSignedUserOperation",
				params: [signed] as never,
			}),
		).resolves.toBe(`0x${"ab".repeat(32)}`);
		expect(prepare).not.toHaveBeenCalled();
		expect(sign).not.toHaveBeenCalled();
		expect(request).toHaveBeenCalledOnce();
		expect(request.mock.calls[0][0]).toEqual({
			method: "eth_sendUserOperation",
			params: [
				{
					sender,
					nonce: "0x7",
					callData: "0xabcd",
					callGasLimit: "0x186a0",
					verificationGasLimit: "0xdbba0",
					preVerificationGas: "0xc350",
					maxFeePerGas: "0x9",
					maxPriorityFeePerGas: "0x2",
					signature: "0x1234",
					paymaster: signed.paymaster,
					paymasterVerificationGasLimit: "0x7530",
					paymasterPostOpGasLimit: "0x4e20",
					paymasterData: "0x5678",
				},
				entryPoint09Address,
			],
		});
	});

	it("waitForUserOperationReceipt delegates to the bundler", async () => {
		const { provider } = buildProvider(mock.authenticator);
		const receipt = await provider.request({
			method: "waitForUserOperationReceipt",
			params: [`0x${"11".repeat(32)}`] as never,
		});
		expect(receipt).toMatchObject({ success: true });
	});

	it("the userop methods require a connection", async () => {
		const { provider } = buildProvider(mock.authenticator);
		await expect(
			provider.request({
				method: "eth_signUserOperation",
				params: [{}] as never,
			}),
		).rejects.toThrow(/not connected/);
		await expect(
			provider.request({
				method: "eth_prepareUserOperation",
				params: [[]] as never,
			}),
		).rejects.toThrow(/not connected/);
		await expect(
			provider.request({
				method: "eth_sendSignedUserOperation",
				params: [{}] as never,
			}),
		).rejects.toThrow(/not connected/);
	});
});

describe("message signing", () => {
	it("personal_sign signs plain and hex messages for the connected account", async () => {
		const { provider } = buildProvider(mock.authenticator);
		const address = await connect(provider);
		expect(
			await provider.request({
				method: "personal_sign",
				params: ["hello", address] as never,
			}),
		).toMatch(/^0x/);
		expect(
			await provider.request({
				method: "personal_sign",
				params: [toHex("hi"), address] as never,
			}),
		).toMatch(/^0x/);
	});

	it("personal_sign and eth_sign sign the payload the dApp sent, not its hex spelling", async () => {
		const { provider } = buildProvider(mock.authenticator);
		const address = await connect(provider);
		// biome-ignore lint/style/noNonNullAssertion: connected above
		const account = provider.getSmartAccount()!;
		const signMessage = vi.spyOn(account, "signMessage");
		const signedHash = () =>
			hashMessage(signMessage.mock.lastCall?.[0].message as SignableMessage);

		await provider.request({
			method: "personal_sign",
			params: ["hi", address] as never,
		});
		expect(signedHash()).toBe(hashMessage("hi"));

		await provider.request({
			method: "personal_sign",
			params: [toHex("hi"), address] as never,
		});
		expect(signedHash()).toBe(hashMessage("hi"));

		const hash = `0x${"ab".repeat(32)}` as const;
		await provider.request({
			method: "eth_sign",
			params: [address, hash] as never,
		});
		expect(signedHash()).toBe(hashMessage({ raw: hash }));
	});

	it("personal_sign rejects when disconnected or on address mismatch", async () => {
		const { provider } = buildProvider(mock.authenticator);
		await expect(
			provider.request({
				method: "personal_sign",
				params: ["hi", WALLET_ADDRESS] as never,
			}),
		).rejects.toThrow(/not connected/);
		await connect(provider);
		await expect(
			provider.request({
				method: "personal_sign",
				params: ["hi", "0x00000000000000000000000000000000deadbeef"] as never,
			}),
		).rejects.toThrow(/Address mismatch/);
	});

	it("eth_sign signs with reversed [address, message] argument order", async () => {
		const { provider } = buildProvider(mock.authenticator);
		const address = await connect(provider);
		expect(
			await provider.request({
				method: "eth_sign",
				params: [address, `0x${"ab".repeat(32)}`] as never,
			}),
		).toMatch(/^0x/);
		await expect(
			provider.request({
				method: "eth_sign",
				params: ["0x00000000000000000000000000000000deadbeef", "0x00"] as never,
			}),
		).rejects.toThrow(/Address mismatch/);
	});

	it("eth_signTypedData_v4 accepts a JSON string or an object", async () => {
		const { provider } = buildProvider(mock.authenticator);
		const address = await connect(provider);
		const typedData = {
			domain: {
				name: "X",
				version: "1",
				chainId: TEST_CHAIN_ID,
				verifyingContract: WALLET_ADDRESS,
			},
			types: { Msg: [{ name: "v", type: "string" }] },
			primaryType: "Msg",
			message: { v: "hi" },
		};
		expect(
			await provider.request({
				method: "eth_signTypedData_v4",
				params: [address, JSON.stringify(typedData)] as never,
			}),
		).toMatch(/^0x/);
		expect(
			await provider.request({
				method: "eth_signTypedData_v4",
				params: [address, typedData] as never,
			}),
		).toMatch(/^0x/);
	});
});

describe("reads: eth_call & signed_eth_call", () => {
	it("eth_call delegates to the public client", async () => {
		const { provider } = buildProvider(mock.authenticator);
		expect(
			await provider.request({
				method: "eth_call",
				params: [{ to: WALLET_ADDRESS, data: "0x12345678" }] as never,
			}),
		).toBe("0x");
	});

	it("signed_eth_call falls back to a plain call when disconnected", async () => {
		const { provider } = buildProvider(mock.authenticator);
		expect(
			await provider.request({
				method: "signed_eth_call",
				params: [{ to: WALLET_ADDRESS, data: "0x12345678" }] as never,
			}),
		).toBe("0x");
	});

	it("signed_eth_call falls back to a plain call when the account is not deployed", async () => {
		const { provider } = buildProvider(mock.authenticator, {
			transportOptions: { code: (i) => (i < 2 ? "0xabcd" : "0x") },
		});
		await connect(provider); // uses deployed code for the connect checks
		// subsequent getCode returns '0x' → treated as undeployed → fallback
		expect(
			await provider.request({
				method: "signed_eth_call",
				params: [{ to: WALLET_ADDRESS, data: "0x12345678" }] as never,
			}),
		).toBe("0x");
	});

	it("signed_eth_call performs an authenticated static call when deployed", async () => {
		const { provider } = buildProvider(mock.authenticator, {
			transportOptions: { code: "0xabcd", staticCallResult: "0xc0ffee" },
		});
		await connect(provider);
		const result = await provider.request({
			method: "signed_eth_call",
			params: [
				{ to: "0x1111111111111111111111111111111111111111", data: "0xabcd" },
			] as never,
		});
		expect(result).toBe("0xc0ffee");
	});

	it("signed_eth_call signs each read over its own target and data, and reuses it only for that read", async () => {
		const staticCalls: {
			target: string;
			data: string;
			signedAt: bigint;
			signature: string;
		}[] = [];
		const { provider } = buildProvider(mock.authenticator, {
			transportOptions: {
				code: "0xabcd",
				staticCallResult: "0xc0ffee",
				onRequest: (method, params) => {
					if (method !== "eth_call") return;
					const { data } = (params as [{ data: `0x${string}` }])[0];
					try {
						const decoded = decodeFunctionData({
							abi: gianoSmartWalletAbi,
							data,
						});
						if (decoded.functionName === "signedStaticCall")
							staticCalls.push(decoded.args[0] as never);
					} catch {
						// not a wallet call
					}
				},
			},
		});
		await connect(provider);
		const prompts = countPasskeyPrompts(mock.authenticator);
		const read = (to: string, data: string) =>
			provider.request({
				method: "signed_eth_call",
				params: [{ to, data }] as never,
			});
		const A = "0x1111111111111111111111111111111111111111";
		const B = "0x2222222222222222222222222222222222222222";

		await read(A, "0xabcd");
		await read(A, "0xabcd"); // same read: cached signature
		await read(A, "0xabce"); // other calldata: new signature
		await read(B, "0xabcd"); // other target: new signature

		expect(prompts.count).toBe(3);
		expect(staticCalls.map((c) => [c.target, c.data])).toEqual([
			[A, "0xabcd"],
			[A, "0xabcd"],
			[A, "0xabce"],
			[B, "0xabcd"],
		]);
		expect(staticCalls[1].signature).toBe(staticCalls[0].signature);
		expect(new Set(staticCalls.map((c) => c.signature)).size).toBe(3);
		// the mock's latest block is at 1_800_000_000; signedAt is set 30 seconds earlier
		expect(staticCalls[0].signedAt).toBe(1_799_999_970n);
	});

	it("signed_eth_call validates to and data before it asks for a signature", async () => {
		const { provider } = buildProvider(mock.authenticator, {
			transportOptions: { code: "0xabcd" },
		});
		await connect(provider);
		const prompts = countPasskeyPrompts(mock.authenticator);
		await expect(
			provider.request({
				method: "signed_eth_call",
				params: [{ data: "0xabcd" } as never],
			}),
		).rejects.toThrow(/`transaction.to` is required/);
		expect(prompts.count).toBe(0);
	});

	it("signed_eth_call requires to and data", async () => {
		const { provider } = buildProvider(mock.authenticator, {
			transportOptions: { code: "0xabcd" },
		});
		await connect(provider);
		await expect(
			provider.request({
				method: "signed_eth_call",
				params: [{ data: "0xabcd" } as never],
			}),
		).rejects.toThrow(/`transaction.to` is required/);
		await expect(
			provider.request({
				method: "signed_eth_call",
				params: [{ to: WALLET_ADDRESS } as never],
			}),
		).rejects.toThrow(/`transaction.data` is required/);
	});
});

describe("signed_eth_call signature cache", () => {
	const A = "0x1111111111111111111111111111111111111111";
	// the mock's default signature lifetime, in seconds
	const LIFETIME = 3600;
	// the lifetime minus the 30-second back-date and the 60-second renewal margin
	const USABLE_MS = (LIFETIME - 30 - 60) * 1000;
	// the mock's latest block timestamp, in ms
	const CHAIN_NOW_MS = 1_800_000_000_000;

	afterEach(() => vi.restoreAllMocks());

	const walletError = (
		errorName: "StaticCallInvalidSignature" | "StaticCallSignatureExpired",
	): Hex =>
		errorName === "StaticCallInvalidSignature"
			? encodeErrorResult({ abi: gianoSmartWalletAbi, errorName })
			: encodeErrorResult({
					abi: gianoSmartWalletAbi,
					errorName,
					args: [1n, 2n],
				});

	async function setup(
		transportOptions: MockClientOptions = {},
		duringPrompt?: () => Promise<void>,
	) {
		const { provider } = buildProvider(mock.authenticator, {
			transportOptions: {
				code: "0xabcd",
				staticCallResult: "0xc0ffee",
				...transportOptions,
			},
		});
		await connect(provider);
		const prompts = countPasskeyPrompts(mock.authenticator, duringPrompt);
		const read = (data: Hex = "0xabcd") =>
			provider.request({
				method: "signed_eth_call",
				params: [{ to: A, data }] as never,
			});
		return { provider, prompts, read };
	}

	it("renews a signature on the local clock, counted from when it was signed", async () => {
		const { prompts, read } = await setup();
		const now = vi.spyOn(Date, "now").mockReturnValue(CHAIN_NOW_MS);

		await read();
		now.mockReturnValue(CHAIN_NOW_MS + USABLE_MS - 1);
		await read();
		expect(prompts.count).toBe(1);

		now.mockReturnValue(CHAIN_NOW_MS + USABLE_MS);
		await read();
		expect(prompts.count).toBe(2);
	});

	it("reuses a signature when the local clock is far from the chain's", async () => {
		const { prompts, read } = await setup();
		const now = vi.spyOn(Date, "now");
		const day = 86_400_000;

		// local clock one day ahead of the chain
		now.mockReturnValue(CHAIN_NOW_MS + day);
		await read("0xabcd");
		await read("0xabcd");
		expect(prompts.count).toBe(1);

		// local clock one day behind the chain
		now.mockReturnValue(CHAIN_NOW_MS - day);
		await read("0xabce");
		await read("0xabce");
		expect(prompts.count).toBe(2);
	});

	it("signs again once when the wallet rejects a cached signature", async () => {
		const { prompts, read } = await setup({
			// the second read finds the chain past the cached signature's limit
			staticCallRevert: (i) =>
				i === 1 ? walletError("StaticCallSignatureExpired") : undefined,
		});

		await read();
		expect(await read()).toBe("0xc0ffee");
		expect(prompts.count).toBe(2);

		// the new signature replaced the rejected one
		await read();
		expect(prompts.count).toBe(2);
	});

	it("does not cache or retry a new signature the wallet rejects", async () => {
		let walletCalls = 0;
		const { prompts, read } = await setup({
			staticCallRevert: () => {
				walletCalls += 1;
				return walletError("StaticCallInvalidSignature");
			},
		});

		await expect(read()).rejects.toThrow(/StaticCallInvalidSignature/);
		expect([prompts.count, walletCalls]).toEqual([1, 1]);
		// a cached copy would be sent first and then retried: two wallet calls
		await expect(read()).rejects.toThrow(/StaticCallInvalidSignature/);
		expect([prompts.count, walletCalls]).toEqual([2, 2]);
	});

	it("removes the new signature too when the wallet rejects the retry", async () => {
		let walletCalls = 0;
		const { prompts, read } = await setup({
			staticCallRevert: (i) => {
				walletCalls += 1;
				if (i === 1) return walletError("StaticCallSignatureExpired");
				if (i === 2) return walletError("StaticCallInvalidSignature");
				return undefined;
			},
		});

		await read();
		// the cached signature is rejected, and so is the new one
		await expect(read()).rejects.toThrow(/StaticCallInvalidSignature/);
		expect([prompts.count, walletCalls]).toEqual([2, 3]);

		// the next read signs again instead of sending the rejected signature
		expect(await read()).toBe("0xc0ffee");
		expect([prompts.count, walletCalls]).toEqual([3, 4]);
	});

	it("keeps the signature when the target reverts with an error named like the wallet's", async () => {
		let walletCalls = 0;
		const { prompts, read } = await setup({
			// PrivateERC20 declares its own InvalidSignature(); the wallet passes it through
			staticCallRevert: (i) => {
				walletCalls += 1;
				return i === 1
					? encodeErrorResult({
							abi: [{ type: "error", name: "InvalidSignature", inputs: [] }],
							errorName: "InvalidSignature",
						})
					: undefined;
			},
		});

		await read();
		await expect(read()).rejects.toThrow();
		// no new signature and no retry
		expect([prompts.count, walletCalls]).toEqual([1, 2]);
		expect(await read()).toBe("0xc0ffee");
		expect(prompts.count).toBe(1);
	});

	it("does not sign, cache or send for a session that ended during the read", async () => {
		let walletCalls = 0;
		let disconnect = () => Promise.resolve();
		const { provider, prompts, read } = await setup(
			{
				staticCallRevert: () => {
					walletCalls += 1;
					return undefined;
				},
			},
			// the user disconnects while the first passkey prompt is open
			() => disconnect(),
		);
		disconnect = async () => {
			disconnect = () => Promise.resolve();
			await provider.request({
				method: "wallet_revokePermissions",
				params: [{}] as never,
			});
		};

		// the second read waits in the signing queue behind the first
		const results = await Promise.allSettled([read("0xabcd"), read("0xabce")]);

		for (const result of results) {
			expect(result.status).toBe("rejected");
			expect((result as PromiseRejectedResult).reason.message).toMatch(
				/session changed/,
			);
		}
		// one prompt for the first read; the queued read never prompted; nothing was sent
		expect([prompts.count, walletCalls]).toEqual([1, 0]);
	});

	it("does not send the fallback read when the session ends during the deployment check", async () => {
		let targetReads = 0;
		let onDeploymentCheck: (() => Promise<void>) | undefined;
		const { provider, read } = await setup({
			// deployed for the connect check, then not deployed, so the read falls back to a
			// plain eth_call
			code: (i) => (i < 1 ? "0xabcd" : "0x"),
			onRequest: async (method, params) => {
				if (method === "eth_call" && (params as [{ to: string }])[0].to === A)
					targetReads += 1;
				if (method !== "eth_getCode" || !onDeploymentCheck) return;
				const hook = onDeploymentCheck;
				onDeploymentCheck = undefined;
				await hook();
			},
		});
		// the user disconnects while the provider checks whether the account is deployed
		onDeploymentCheck = async () => {
			await provider.request({
				method: "wallet_revokePermissions",
				params: [{}] as never,
			});
		};

		await expect(read()).rejects.toThrow(/session changed/);
		expect(targetReads).toBe(0);
	});

	it("does not prompt when the session ends during the block lookup", async () => {
		let walletCalls = 0;
		let onBlockLookup: (() => Promise<void>) | undefined;
		const { provider, prompts, read } = await setup({
			onRequest: async (method) => {
				if (method !== "eth_getBlockByNumber" || !onBlockLookup) return;
				const hook = onBlockLookup;
				onBlockLookup = undefined;
				await hook();
			},
			staticCallRevert: () => {
				walletCalls += 1;
				return undefined;
			},
		});
		// the user disconnects while the provider fetches the latest block for signedAt
		onBlockLookup = async () => {
			await provider.request({
				method: "wallet_revokePermissions",
				params: [{}] as never,
			});
		};

		await expect(read()).rejects.toThrow(/session changed/);
		expect([prompts.count, walletCalls]).toEqual([0, 0]);
	});

	it("uses a replacement another read already signed when a delayed rejection arrives", async () => {
		let releaseSecondRejection = () => {};
		const secondRejection = new Promise<Hex>((resolve) => {
			releaseSecondRejection = () =>
				resolve(walletError("StaticCallSignatureExpired"));
		});
		const { prompts, read } = await setup({
			staticCallRevert: (i) => {
				// 0: the first read signs and caches S
				// 1 and 2: two identical reads send S, and the wallet rejects both
				if (i === 1) return walletError("StaticCallSignatureExpired");
				if (i === 2) return secondRejection;
				// 3: the first rejected read sends its replacement S'; only now does the
				//    second rejection arrive
				if (i === 3) releaseSecondRejection();
				return undefined;
			},
		});

		await read();
		const results = await Promise.all([read(), read()]);

		expect(results).toEqual(["0xc0ffee", "0xc0ffee"]);
		// S and S': the second read used S' instead of signing a third time
		expect(prompts.count).toBe(2);
	});

	it("keeps the signature when the read itself reverts", async () => {
		const { prompts, read } = await setup({
			// an error from the target contract, not from the wallet
			staticCallRevert: (i) => (i === 0 ? "0xdeadbeef" : undefined),
		});

		await expect(read()).rejects.toThrow();
		expect(await read()).toBe("0xc0ffee");
		expect(prompts.count).toBe(1);
	});

	it("signs identical concurrent reads once, and one signature at a time", async () => {
		const { prompts, read } = await setup();

		const results = await Promise.all([
			read("0xabcd"),
			read("0xabcd"),
			read("0xabce"),
		]);

		expect(results).toEqual(["0xc0ffee", "0xc0ffee", "0xc0ffee"]);
		expect(prompts.count).toBe(2);
		expect(prompts.maxActive).toBe(1);
	});
});

describe("request routing & events", () => {
	it("delegates unknown methods to the public client", async () => {
		const onRequest = vi.fn();
		const { provider } = buildProvider(mock.authenticator, {
			transportOptions: { onRequest },
		});
		await provider.request({ method: "eth_chainId" as never }); // handled locally
		await provider.request({
			method: "eth_getCode",
			params: [WALLET_ADDRESS, "latest"],
		} as never); // pass-through
		expect(onRequest).toHaveBeenCalledWith("eth_getCode", expect.anything());
	});

	it("logs and rethrows handler errors via the injected logger", async () => {
		const logger = { debug: vi.fn(), warn: vi.fn(), error: vi.fn() };
		const { provider } = buildProvider(mock.authenticator, {
			overrides: { logger },
		});
		await expect(
			provider.request({
				method: "eth_sendTransaction",
				params: [{ to: "0x1111111111111111111111111111111111111111" }] as never,
			}),
		).rejects.toThrow();
		expect(logger.error).toHaveBeenCalled();
	});

	it("removeListener detaches a handler", async () => {
		const { provider } = buildProvider(mock.authenticator);
		const handler = vi.fn();
		provider.on("connect", handler);
		provider.removeListener("connect", handler);
		await connect(provider);
		expect(handler).not.toHaveBeenCalled();
	});

	it("uses a custom estimateFeesPerGas fallback", async () => {
		const estimateFeesPerGas = vi.fn(async () => ({
			maxFeePerGas: parseGwei("5"),
			maxPriorityFeePerGas: parseGwei("1"),
		}));
		const { provider } = buildProvider(mock.authenticator, {
			overrides: { estimateFeesPerGas },
		});
		await connect(provider);
		await provider.request({
			method: "eth_prepareUserOperation",
			params: [
				[
					{
						to: "0x1111111111111111111111111111111111111111",
						value: 0n,
						data: "0x",
					},
				],
			] as never,
		});
		expect(estimateFeesPerGas).toHaveBeenCalled();
	});
});
