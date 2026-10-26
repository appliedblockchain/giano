import { gianoSmartWalletAbi } from "@appliedblockchain/giano-contracts";
import * as WebAuthnP256 from "ox/WebAuthnP256";
import {
	decodeAbiParameters,
	encodeFunctionData,
	hashMessage,
	hashTypedData,
	hexToBytes,
	size,
	toHex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	parseDerSignature,
	sign as signHelper,
	signTypedData as signTypedDataHelper,
	toGianoSmartAccount,
	toWebAuthnSignature,
	wrapSignature,
} from "../src/account/toGianoSmartAccount";
import {
	createMockClient,
	createWebAuthnOwner,
	FACTORY_ADDRESS,
	WALLET_ADDRESS,
} from "./helpers";
import {
	type InstalledWebAuthnMock,
	installWebAuthnMock,
} from "./webauthn-mock";

const LOCAL_PK =
	"0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as const;
const localOwner = privateKeyToAccount(LOCAL_PK);
const ADDRESS_OWNER = "0x00000000000000000000000000000000000000aa" as const;
const HASH = `0x${"cd".repeat(32)}` as const;

let mock: InstalledWebAuthnMock;
beforeEach(() => {
	mock = installWebAuthnMock();
});
afterEach(() => mock.uninstall());

const decodeWrapped = (wrapped: `0x${string}`) =>
	decodeAbiParameters(
		[
			{
				components: [
					{ name: "ownerBytes", type: "bytes" },
					{ name: "signatureData", type: "bytes" },
				],
				type: "tuple",
			},
		],
		wrapped,
	)[0];

describe("toGianoSmartAccount — calls encoding", () => {
	it("encodes a single call as execute and a batch as executeBatch", async () => {
		const { client } = createMockClient();
		const account = await toGianoSmartAccount({
			client,
			owners: [ADDRESS_OWNER],
			factoryAddress: FACTORY_ADDRESS,
			address: WALLET_ADDRESS,
		});

		const single = await account.encodeCalls([
			{
				to: "0x1111111111111111111111111111111111111111",
				value: 1n,
				data: "0x",
			},
		]);
		expect(single.slice(0, 10)).toBe(
			encodeFunctionData({
				abi: gianoSmartWalletAbi,
				functionName: "execute",
				args: ["0x1111111111111111111111111111111111111111", 1n, "0x"],
			}).slice(0, 10),
		);

		const batch = await account.encodeCalls([
			{
				to: "0x1111111111111111111111111111111111111111",
				value: 1n,
				data: "0x",
			},
			{
				to: "0x2222222222222222222222222222222222222222",
				value: 2n,
				data: "0xabcd",
			},
		]);
		expect(batch.slice(0, 10)).toBe(
			encodeFunctionData({
				abi: gianoSmartWalletAbi,
				functionName: "executeBatch",
				args: [[]],
			}).slice(0, 10),
		);
	});

	it("decodes execute and executeBatch calldata, and rejects other functions", async () => {
		const { client } = createMockClient();
		const account = await toGianoSmartAccount({
			client,
			owners: [ADDRESS_OWNER],
			factoryAddress: FACTORY_ADDRESS,
			address: WALLET_ADDRESS,
		});

		const executeData = encodeFunctionData({
			abi: gianoSmartWalletAbi,
			functionName: "execute",
			args: ["0x1111111111111111111111111111111111111111", 5n, "0xdead"],
		});
		expect(await account.decodeCalls(executeData)).toEqual([
			{
				to: "0x1111111111111111111111111111111111111111",
				value: 5n,
				data: "0xdead",
			},
		]);

		const batchData = encodeFunctionData({
			abi: gianoSmartWalletAbi,
			functionName: "executeBatch",
			args: [
				[
					{
						target: "0x2222222222222222222222222222222222222222",
						value: 2n,
						data: "0xbeef",
					},
				],
			],
		});
		expect(await account.decodeCalls(batchData)).toEqual([
			{
				to: "0x2222222222222222222222222222222222222222",
				value: 2n,
				data: "0xbeef",
			},
		]);

		const otherData = encodeFunctionData({
			abi: gianoSmartWalletAbi,
			functionName: "getSignatureLifetime",
		});
		await expect(account.decodeCalls(otherData)).rejects.toThrow(
			/unable to decode calls/,
		);
	});
});

describe("toGianoSmartAccount — address & factory", () => {
	it("resolves the counterfactual address via the factory and caches it", async () => {
		let calls = 0;
		const { client } = createMockClient({
			walletAddress: WALLET_ADDRESS,
			onRequest: (m) => {
				if (m === "eth_call") calls += 1;
			},
		});
		const account = await toGianoSmartAccount({
			client,
			owners: [ADDRESS_OWNER],
			factoryAddress: FACTORY_ADDRESS,
		});

		expect((await account.getAddress()).toLowerCase()).toBe(
			WALLET_ADDRESS.toLowerCase(),
		);
		await account.getAddress();
		expect(calls).toBe(1); // second call served from cache
	});

	it("returns factory + createAccount calldata from getFactoryArgs", async () => {
		const { client } = createMockClient();
		const account = await toGianoSmartAccount({
			client,
			owners: [ADDRESS_OWNER],
			factoryAddress: FACTORY_ADDRESS,
			address: WALLET_ADDRESS,
		});
		const { factory, factoryData } = await account.getFactoryArgs();
		expect(factory).toBe(FACTORY_ADDRESS);
		expect(factoryData?.slice(0, 10)).toBe(
			encodeFunctionData({
				abi: (await import("@appliedblockchain/giano-contracts"))
					.gianoSmartWalletFactoryAbi,
				functionName: "createAccount",
				args: [[], 0n],
			}).slice(0, 10),
		);
	});

	it("rejects an unknown owner type", async () => {
		const { client } = createMockClient();
		await expect(
			toGianoSmartAccount({
				client,
				owners: [{ type: "bogus" } as never],
				factoryAddress: FACTORY_ADDRESS,
			}),
		).rejects.toThrow(/invalid owner type/);
	});
});

describe("toGianoSmartAccount — stub signature & gas", () => {
	it("returns the Coinbase-style webauthn stub for a webAuthn owner", async () => {
		const { owner } = await createWebAuthnOwner(mock.authenticator);
		const { client } = createMockClient();
		const account = await toGianoSmartAccount({
			client,
			owners: [owner],
			factoryAddress: FACTORY_ADDRESS,
			address: WALLET_ADDRESS,
		});
		const stub = await account.getStubSignature();
		expect(stub.length).toBeGreaterThan(1000); // the large fixed webauthn envelope
	});

	it("returns a wrapped ECDSA stub for a non-webAuthn owner", async () => {
		const { client } = createMockClient();
		const account = await toGianoSmartAccount({
			client,
			owners: [ADDRESS_OWNER],
			factoryAddress: FACTORY_ADDRESS,
			address: WALLET_ADDRESS,
		});
		const stub = await account.getStubSignature();
		const decoded = decodeWrapped(stub);
		expect(size(decoded.signatureData)).toBe(65); // r||s||v
	});

	it("raises the verification gas floor for webAuthn owners only", async () => {
		const { owner } = await createWebAuthnOwner(mock.authenticator);
		const { client } = createMockClient();
		const webAuthnAccount = await toGianoSmartAccount({
			client,
			owners: [owner],
			factoryAddress: FACTORY_ADDRESS,
			address: WALLET_ADDRESS,
		});
		expect(
			await webAuthnAccount.userOperation!.estimateGas!({
				verificationGasLimit: 1n,
			} as never),
		).toEqual({ verificationGasLimit: 800_000n });

		const addressAccount = await toGianoSmartAccount({
			client,
			owners: [ADDRESS_OWNER],
			factoryAddress: FACTORY_ADDRESS,
			address: WALLET_ADDRESS,
		});
		expect(
			await addressAccount.userOperation!.estimateGas!({} as never),
		).toBeUndefined();
	});
});

describe("toGianoSmartAccount — signing (real webauthn crypto)", () => {
	it("signs a hash, a message, typed data and a user operation with a real passkey", async () => {
		const { owner } = await createWebAuthnOwner(mock.authenticator);
		// Deployed account so viem returns the raw Giano signature (undeployed accounts get ERC-6492-wrapped).
		const { client } = createMockClient({ code: "0xdeadbeef" });
		const account = await toGianoSmartAccount({
			client,
			owners: [owner],
			factoryAddress: FACTORY_ADDRESS,
			address: WALLET_ADDRESS,
		});

		for (const wrapped of [
			await account.sign({ hash: HASH }),
			await account.signMessage({ message: "hello giano" }),
			await account.signTypedData({
				domain: {
					name: "X",
					version: "1",
					chainId: 31337,
					verifyingContract: WALLET_ADDRESS,
				},
				types: { Msg: [{ name: "v", type: "string" }] },
				primaryType: "Msg",
				message: { v: "hi" },
			}),
			await account.signUserOperation({
				callData: "0x",
				callGasLimit: 1n,
				verificationGasLimit: 1n,
				preVerificationGas: 1n,
				maxFeePerGas: 1n,
				maxPriorityFeePerGas: 1n,
				nonce: 0n,
				signature: "0x",
			} as never),
		]) {
			const decoded = decodeWrapped(wrapped);
			// WebAuthn envelope is passed through unchanged (not a 65-byte ECDSA sig).
			expect(size(decoded.signatureData)).toBeGreaterThan(65);
		}
	});

	it("ERC-6492-wraps signatures for an undeployed account", async () => {
		const { owner } = await createWebAuthnOwner(mock.authenticator);
		const { client } = createMockClient({ code: "0x" }); // not deployed
		const account = await toGianoSmartAccount({
			client,
			owners: [owner],
			factoryAddress: FACTORY_ADDRESS,
			address: WALLET_ADDRESS,
		});
		const wrapped = await account.signMessage({ message: "hi" });
		// ERC-6492 magic suffix.
		expect(
			wrapped.endsWith(
				"6492649264926492649264926492649264926492649264926492649264926492",
			),
		).toBe(true);
	});

	it("produces a static-call permission signature with a unix timestamp", async () => {
		const { owner } = await createWebAuthnOwner(mock.authenticator);
		const { client } = createMockClient();
		const account = await toGianoSmartAccount({
			client,
			owners: [owner],
			factoryAddress: FACTORY_ADDRESS,
			address: WALLET_ADDRESS,
		});
		const { signature, signedAt } = await account.signStaticCallPermission();
		expect(signedAt).toBeGreaterThan(1_600_000_000); // a real unix timestamp (seconds)
		expect(signature.startsWith("0x")).toBe(true);
	});

	it("refuses to sign with an address-only owner", async () => {
		const { client } = createMockClient();
		const account = await toGianoSmartAccount({
			client,
			owners: [ADDRESS_OWNER],
			factoryAddress: FACTORY_ADDRESS,
			address: WALLET_ADDRESS,
		});
		await expect(account.sign({ hash: HASH })).rejects.toThrow(
			/owner cannot sign/,
		);
		await expect(account.signMessage({ message: "x" })).rejects.toThrow(
			/owner cannot sign/,
		);
	});
});

describe("signing helpers", () => {
	it("sign(): dispatches to a local account and throws for raw-sign-less owners", async () => {
		const local = await signHelper({ hash: HASH, owner: localOwner });
		expect(size(local)).toBe(65);
		await expect(
			signHelper({ hash: HASH, owner: { type: "local" } as never }),
		).rejects.toThrow(/does not support raw sign/);
	});

	it("signTypedData(): prefers a local account signTypedData, else hashes and signs", async () => {
		const typedData = {
			domain: {
				name: "X",
				version: "1",
				chainId: 31337,
				verifyingContract: WALLET_ADDRESS,
			},
			types: { Msg: [{ name: "v", type: "string" }] },
			primaryType: "Msg" as const,
			message: { v: "hi" },
		};
		const viaLocal = await signTypedDataHelper({
			typedData,
			owner: localOwner,
		});
		expect(size(viaLocal)).toBe(65);

		// owner without signTypedData but with sign → falls back to hashing the typed data + raw sign
		const rawSigner = {
			type: "local",
			sign: async ({ hash }: { hash: `0x${string}` }) => hash,
		} as never;
		const viaFallback = await signTypedDataHelper({
			typedData,
			owner: rawSigner,
		});
		expect(viaFallback).toBe(hashTypedData(typedData));
	});

	it("toWebAuthnSignature() ABI-encodes the webauthn tuple", () => {
		const encoded = toWebAuthnSignature({
			webauthn: {
				authenticatorData: "0xaabb",
				clientDataJSON: '{"type":"webauthn.get"}',
				challengeIndex: 1,
				typeIndex: 0,
			} as never,
			signature: `0x${"11".repeat(32)}${"22".repeat(32)}1b`,
		});
		expect(encoded.startsWith("0x")).toBe(true);
		expect(size(encoded)).toBeGreaterThan(100);
	});

	it("toWebAuthnSignature() takes r and s from the assertion DER when the raw credential is present", () => {
		const webauthn = {
			authenticatorData: "0xaabb",
			clientDataJSON: '{"type":"webauthn.get"}',
			challengeIndex: 1,
			typeIndex: 0,
		} as never;
		const raw = {
			response: { signature: bytes(CI_ASSERTION.der).buffer },
		} as never;
		// A deliberately wrong pre-parsed signature: the DER bytes must win.
		const encoded = toWebAuthnSignature({
			webauthn,
			raw,
			signature: `0x${"11".repeat(32)}${"22".repeat(32)}1b`,
		});
		const [auth] = decodeAbiParameters(WEBAUTHN_AUTH, encoded);
		expect(auth.r).toBe(CI_ASSERTION.r);
		expect(auth.s).toBe(CI_ASSERTION.s);
	});

	it("wrapSignature(): converts 65-byte ECDSA to packed r||s||v, passes others through", () => {
		const packed = decodeWrapped(
			wrapSignature({
				ownerBytes: "0x1234",
				signature: `0x${"aa".repeat(32)}${"bb".repeat(32)}1b`,
			}),
		);
		expect(size(packed.signatureData)).toBe(65);
		const passthrough = decodeWrapped(
			wrapSignature({
				ownerBytes: "0x1234",
				signature: `0x${"cc".repeat(80)}`,
			}),
		);
		expect(size(passthrough.signatureData)).toBe(80);
	});
});

const P256_N =
	0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const bytes = (hex: `0x${string}`) => hexToBytes(hex);
const WEBAUTHN_AUTH = [
	{
		type: "tuple",
		components: [
			{ name: "authenticatorData", type: "bytes" },
			{ name: "clientDataJSON", type: "bytes" },
			{ name: "challengeIndex", type: "uint256" },
			{ name: "typeIndex", type: "uint256" },
			{ name: "r", type: "uint256" },
			{ name: "s", type: "uint256" },
		],
	},
] as const;

/**
 * An assertion Chrome's virtual authenticator produced in CI (e2e demo, `signed_eth_call`) whose
 * `r` has a leading zero byte: 31 significant bytes, DER-encoded as `0x00 ‖ r` since its top bit is
 * set. ox's `parseAsn1Signature` skipped the sign byte, then still read 32 bytes — `oxR`, the real
 * `r` shifted left a byte with `s`'s INTEGER tag (0x02) appended — and the account reverted with
 * `InvalidSignature()`.
 */
const CI_ASSERTION = {
	publicKey: {
		prefix: 4,
		x: 0xccfe4b964a95af006a41b2e4c2e2e97d7426804ff6d976d83ec08b8071bd0e98n,
		y: 0x94f7e191c80ac744305cbcddb843021d299f25eb2e4dec2f05973d2cc95b8ac9n,
	},
	challenge:
		"0x45e5f8a0c5c479242055ec52cbf8fc8f88aa315848cc610f8d2b82dd8d558536",
	metadata: {
		authenticatorData:
			"0x3e577a876bdd38128dfdf43bf76f01dec1224748c490abf31ab00cce0f635a72050000000d",
		clientDataJSON:
			'{"type":"webauthn.get","challenge":"ReX4oMXEeSQgVexSy_j8j4iqMVhIzGEPjSuC3Y1VhTY","origin":"http://wallet.localhost","crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}',
		challengeIndex: 23,
		typeIndex: 1,
		userVerificationRequired: false,
	},
	der: "0x3044022000d5a2c53a3078628d8793ecd382f49479a5661db3cc3845c287d9a4fb0e3f8f02202a64308b09f3cda68769c70b303ddc738da3decc40e40c81eccb9c05595aab64",
	r: 0xd5a2c53a3078628d8793ecd382f49479a5661db3cc3845c287d9a4fb0e3f8fn,
	s: 0x2a64308b09f3cda68769c70b303ddc738da3decc40e40c81eccb9c05595aab64n,
	oxR: 0xd5a2c53a3078628d8793ecd382f49479a5661db3cc3845c287d9a4fb0e3f8f02n,
} as const;

describe("parseDerSignature", () => {
	const verifies = (r: bigint, s: bigint) =>
		WebAuthnP256.verify({
			challenge: CI_ASSERTION.challenge,
			metadata: CI_ASSERTION.metadata,
			publicKey: CI_ASSERTION.publicKey,
			signature: { r, s },
		});

	it("decodes a 31-byte r that ox misreads, into a signature that verifies", () => {
		const { r, s } = parseDerSignature(bytes(CI_ASSERTION.der));
		expect(r).toBe(CI_ASSERTION.r);
		expect(s).toBe(CI_ASSERTION.s);
		expect(verifies(r, s)).toBe(true);
		expect(verifies(CI_ASSERTION.oxR, CI_ASSERTION.s)).toBe(false);
	});

	it("decodes short, sign-padded and full-width integers alike", () => {
		const der = (r: string, s: string) => {
			const int = (hex: string) =>
				`02${(hex.length / 2).toString(16).padStart(2, "0")}${hex}`;
			const body = int(r) + int(s);
			return bytes(
				`0x30${(body.length / 2).toString(16).padStart(2, "0")}${body}`,
			);
		};
		expect(parseDerSignature(der("7f".repeat(32), "01"))).toEqual({
			r: BigInt(`0x${"7f".repeat(32)}`),
			s: 1n,
		});
		expect(parseDerSignature(der(`00${"80".repeat(32)}`, "1234"))).toEqual({
			r: BigInt(`0x${"80".repeat(32)}`),
			s: 0x1234n,
		});
	});

	it("normalizes a high s to n - s", () => {
		const high = P256_N - CI_ASSERTION.s;
		const body = `0220${CI_ASSERTION.der.slice(10, 74)}0221${high.toString(16).padStart(66, "0")}`;
		const { s } = parseDerSignature(
			bytes(`0x30${(body.length / 2).toString(16)}${body}`),
		);
		expect(s).toBe(CI_ASSERTION.s);
	});

	it("rejects malformed DER", () => {
		expect(() => parseDerSignature(bytes("0x3100"))).toThrow(
			/not a DER sequence/,
		);
		expect(() => parseDerSignature(bytes(`${CI_ASSERTION.der}00`))).toThrow(
			/not a DER sequence/,
		);
		expect(() => parseDerSignature(bytes("0x3006020101030101"))).toThrow(
			/expected a DER integer/,
		);
		expect(() => parseDerSignature(bytes("0x3006020100020101"))).toThrow(
			/out of range/,
		);
	});
});

// sanity that hashMessage/toHex imports are exercised (keeps eslint honest)
describe("sanity", () => {
	it("hashes are 32 bytes", () => {
		expect(size(hashMessage("x"))).toBe(32);
		expect(toHex("a")).toBe("0x61");
	});
});
