import {
	createWebAuthnCredential,
	toWebAuthnAccount,
} from "viem/account-abstraction";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getCredential } from "../src/account/get-credential";
import { getWebAuthnAccount } from "../src/account/get-web-authn-account";
import {
	passkeyCredentialCreate,
	passkeyCredentialGet,
	resolvePasskeyDevicePreference,
	withPasskeyDevicePreference,
} from "../src/passkey-device-preference";
import { createWalletApiInjection } from "../src/provider-injection";
import {
	type InstalledWebAuthnMock,
	installWebAuthnMock,
} from "./webauthn-mock";

let mock: InstalledWebAuthnMock;
beforeEach(() => {
	mock = installWebAuthnMock();
});
afterEach(() => {
	vi.restoreAllMocks();
	mock.uninstall();
});

describe("passkey device preference", () => {
	it("validates values without accessing browser credentials", () => {
		expect(resolvePasskeyDevicePreference(undefined)).toBe("browser-default");
		expect(resolvePasskeyDevicePreference("prefer-mobile")).toBe(
			"prefer-mobile",
		);
		for (const value of [null, "phone-only", {}, false]) {
			expect(() => resolvePasskeyDevicePreference(value)).toThrow(
				/passkeyDevicePreference/,
			);
		}
	});

	it("preserves default request identity and security options", () => {
		const request = {
			publicKey: {
				challenge: new Uint8Array([1]),
				userVerification: "required" as const,
				allowCredentials: [
					{ type: "public-key" as const, id: new Uint8Array([2]) },
				],
			},
		};
		expect(withPasskeyDevicePreference(request)).toBe(request);
		expect(withPasskeyDevicePreference(request, "browser-default")).toBe(
			request,
		);
		const preferred = withPasskeyDevicePreference(request, "prefer-mobile");
		expect(preferred).toEqual({
			publicKey: { ...request.publicKey, hints: ["hybrid"] },
		});
		expect(preferred.publicKey.challenge).toBe(request.publicKey.challenge);
		expect(preferred.publicKey.allowCredentials).toBe(
			request.publicKey.allowCredentials,
		);
		expect(request.publicKey).not.toHaveProperty("hints");
	});

	it("decorates real registration, discovery and account signatures without narrowing authenticators", async () => {
		const create = vi.spyOn(navigator.credentials, "create");
		const credential = await createWebAuthnCredential({
			user: { id: new Uint8Array([1]), name: "phone" },
			createFn: passkeyCredentialCreate("prefer-mobile"),
			authenticatorSelection: {
				userVerification: "required",
				residentKey: "required",
			},
		});
		expect(create.mock.calls[0][0]?.publicKey).toMatchObject({
			hints: ["hybrid"],
			authenticatorSelection: { userVerification: "required" },
		});
		expect(
			create.mock.calls[0][0]?.publicKey?.authenticatorSelection,
		).not.toHaveProperty("authenticatorAttachment");
		const get = vi.spyOn(navigator.credentials, "get");
		await getCredential(
			{ credentialId: "user-pick", challenge: new Uint8Array([2]) },
			"prefer-mobile",
		);
		expect(get.mock.calls[0][0]?.publicKey).toMatchObject({
			hints: ["hybrid"],
			userVerification: "required",
		});
		expect(get.mock.calls[0][0]?.publicKey?.allowCredentials).toBeUndefined();
		// Building (or restoring) the account must raise no prompt of its own.
		const beforeBuild = get.mock.calls.length;
		const account = toWebAuthnAccount({
			credential,
			getFn: passkeyCredentialGet("prefer-mobile"),
		});
		expect(get.mock.calls.length).toBe(beforeBuild);
		await account.sign({ hash: `0x${"12".repeat(32)}` });
		await account.signMessage({ message: "hello" });
		// One prompt per signature, so the loop below cannot pass vacuously.
		expect(get.mock.calls.length - beforeBuild).toBe(2);
		for (const [request] of get.mock.calls.slice(beforeBuild)) {
			expect(request?.publicKey).toMatchObject({
				hints: ["hybrid"],
				userVerification: "required",
			});
			expect(request?.publicKey?.allowCredentials?.[0]).not.toHaveProperty(
				"transports",
			);
		}
	});

	it("does not retry a cancelled ceremony on any caller path", async () => {
		const cancelled = () => new DOMException("cancelled", "NotAllowedError");
		const get = vi
			.spyOn(navigator.credentials, "get")
			.mockImplementation(async () => {
				throw cancelled();
			});

		// Selected-credential sign-in through the provider's account builder: a cancel
		// resolves to "no account", after exactly one prompt.
		const injection = {
			onCredentialSignedIn: vi.fn(),
			getPublicKeyByCredentialId: vi.fn(),
		};
		await expect(
			getWebAuthnAccount(
				{ credentialId: "user-pick", challenge: new Uint8Array([1]) },
				injection as never,
				"prefer-mobile",
			),
		).resolves.toBeNull();
		expect(get).toHaveBeenCalledTimes(1);
		expect(injection.onCredentialSignedIn).not.toHaveBeenCalled();

		// Discoverable sign-in through the wallet-api injection.
		get.mockClear();
		const fetchImpl = vi.fn(async () => ({
			ok: true,
			status: 200,
			json: async () => ({ challenge: "AQ" }),
		}));
		const walletApi = createWalletApiInjection({
			apiUrl: "https://wallet.test/api",
			externalUserId: "u",
			passkeyDevicePreference: "prefer-mobile",
			fetch: fetchImpl as never,
		});
		await expect(walletApi.signInWithExistingPasskey()).rejects.toThrow(
			"cancelled",
		);
		expect(get).toHaveBeenCalledTimes(1);
		expect(get.mock.calls[0][0]?.publicKey).toMatchObject({
			hints: ["hybrid"],
		});
		// Only the options request went out; nothing was verified after the cancel.
		expect(fetchImpl).toHaveBeenCalledTimes(1);

		// A signature on an existing account.
		get.mockClear();
		const account = toWebAuthnAccount({
			credential: { id: "AQ", publicKey: `0x${"11".repeat(64)}` },
			getFn: passkeyCredentialGet("prefer-mobile"),
		});
		await expect(
			account.sign({ hash: `0x${"12".repeat(32)}` }),
		).rejects.toThrow("cancelled");
		expect(get).toHaveBeenCalledTimes(1);

		expect(passkeyCredentialGet()).toBeUndefined();
		expect(passkeyCredentialCreate()).toBeUndefined();
	});
});
