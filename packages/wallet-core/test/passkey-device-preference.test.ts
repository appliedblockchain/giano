import {
	createWebAuthnCredential,
	toWebAuthnAccount,
} from "viem/account-abstraction";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getCredential } from "../src/account/get-credential";
import {
	passkeyCredentialCreate,
	passkeyCredentialGet,
	resolvePasskeyDevicePreference,
	withPasskeyDevicePreference,
} from "../src/passkey-device-preference";
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
		const account = toWebAuthnAccount({
			credential,
			getFn: passkeyCredentialGet("prefer-mobile"),
		});
		const before = get.mock.calls.length;
		expect(get.mock.calls).toHaveLength(before);
		await account.sign({ hash: `0x${"12".repeat(32)}` });
		await account.signMessage({ message: "hello" });
		for (const [request] of get.mock.calls.slice(before)) {
			expect(request?.publicKey).toMatchObject({
				hints: ["hybrid"],
				userVerification: "required",
			});
			expect(request?.publicKey?.allowCredentials?.[0]).not.toHaveProperty(
				"transports",
			);
		}
	});

	it("does not retry a cancelled ceremony", async () => {
		const get = vi
			.spyOn(navigator.credentials, "get")
			.mockRejectedValue(new DOMException("cancelled", "NotAllowedError"));
		await expect(
			passkeyCredentialGet("prefer-mobile")?.({
				publicKey: { challenge: new Uint8Array([1]) },
			}),
		).rejects.toThrow("cancelled");
		expect(get).toHaveBeenCalledTimes(1);
		expect(passkeyCredentialGet()).toBeUndefined();
		expect(passkeyCredentialCreate()).toBeUndefined();
	});
});
