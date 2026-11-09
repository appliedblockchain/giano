import { bytesToHex, type Hex, hexToBytes } from "viem";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { InvalidP256PublicKeyError } from "../src/management";
import { createGianoProvider } from "../src/provider";
import type { GianoProviderInjection } from "../src/provider-injection";
import {
	createMockBundler,
	createMockInjection,
	createMockTransport,
	FACTORY_ADDRESS,
	TEST_CHAIN_ID,
	testChain,
} from "./helpers";
import {
	type InstalledWebAuthnMock,
	installWebAuthnMock,
} from "./webauthn-mock";

// The browser rejects an off-curve key before viem returns the credential, so the only way
// to get one into the provider is to change what createWebAuthnCredential returns. This
// mock applies to the whole file, which is why these tests live apart from provider.test.ts.
const tamper = vi.hoisted(() => ({ enabled: false }));
vi.mock("viem/account-abstraction", async (importOriginal) => {
	const original =
		await importOriginal<typeof import("viem/account-abstraction")>();
	return {
		...original,
		createWebAuthnCredential: async (
			...args: Parameters<typeof original.createWebAuthnCredential>
		) => {
			const credential = await original.createWebAuthnCredential(...args);
			if (!tamper.enabled) return credential;
			// Flip one bit of y: the result is no longer a point on the curve.
			const bytes = hexToBytes(credential.publicKey);
			bytes[bytes.length - 1] ^= 0x01;
			return { ...credential, publicKey: bytesToHex(bytes) };
		},
	};
});

let mock: InstalledWebAuthnMock;
beforeEach(() => {
	mock = installWebAuthnMock();
	tamper.enabled = true;
});
afterEach(() => {
	mock.uninstall();
	tamper.enabled = false;
});

function buildProvider(handlerAddress: Hex | null) {
	const onCredentialCreated = vi.fn(async () => handlerAddress);
	const onCredentialKey = vi.fn<GianoProviderInjection["onCredentialKey"]>(
		async () => {},
	);
	const { transport } = createMockTransport({ code: "0xabcd" });
	const { bundler, sentUserOps } = createMockBundler();
	const provider = createGianoProvider({
		initialChainId: TEST_CHAIN_ID,
		bundlers: { [TEST_CHAIN_ID]: bundler },
		chains: [testChain],
		transports: { [TEST_CHAIN_ID]: transport },
		injection: createMockInjection(mock.authenticator, {
			onCredentialCreated,
			onCredentialKey,
		}),
		factoryAddresses: { [TEST_CHAIN_ID]: FACTORY_ADDRESS },
		logger: { debug: () => {}, warn: () => {}, error: () => {} },
	}).gianoProvider;
	return { provider, onCredentialCreated, onCredentialKey, sentUserOps };
}

describe("passkey registration with an invalid public key", () => {
	it.each([
		["the provider deploys the account", null],
		[
			"the handler returns the account address",
			"0x000000000000000000000000000000000000cafe" as Hex,
		],
	])(
		"fails before anything uses the credential when %s",
		async (_, handlerAddress) => {
			const { provider, onCredentialCreated, onCredentialKey, sentUserOps } =
				buildProvider(handlerAddress);

			await expect(
				provider.request({ method: "eth_requestAccounts" }),
			).rejects.toThrow(InvalidP256PublicKeyError);

			// Nothing reached wallet-api, nothing was deployed, and no account was cached.
			expect(onCredentialCreated).not.toHaveBeenCalled();
			expect(onCredentialKey).not.toHaveBeenCalled();
			expect(sentUserOps).toHaveLength(0);
			expect(provider.getSmartAccount()).toBeNull();
			expect(await provider.request({ method: "eth_accounts" })).toEqual([]);
		},
	);

	it("still connects when the key is valid", async () => {
		tamper.enabled = false;
		const { provider, onCredentialCreated, onCredentialKey } =
			buildProvider(null);

		const [address] = await provider.request({ method: "eth_requestAccounts" });

		expect(address).toMatch(/^0x[0-9a-fA-F]{40}$/);
		expect(onCredentialCreated).toHaveBeenCalledOnce();
		expect(onCredentialKey).toHaveBeenCalledWith(
			expect.anything(),
			mock.authenticator.getPublicKeyXY(onCredentialKey.mock.calls[0][0]),
		);
	});
});
