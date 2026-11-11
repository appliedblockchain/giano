import { bytesToHex, type Hex, hexToBytes, pad } from "viem";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	depositPasskeyIntoPendingAddition,
	InvalidP256PublicKeyError,
	ownerFingerprint,
	PendingAdditionKeyMismatchError,
	parseP256PublicKey,
	publicKeyOwnerBytes,
	type WalletManagementApi,
} from "../src/management";
import { toBase64Url } from "../src/provider-injection/wallet-api/serialization";
import {
	type InstalledWebAuthnMock,
	installWebAuthnMock,
} from "./webauthn-mock";

// The browser rejects an off-curve key before viem returns the credential, so the only way
// to get one into the deposit step is to change what createWebAuthnCredential returns. The
// mock also records the key the device created, which wallet-api is expected to echo back.
const created = vi.hoisted(() => ({
	tamper: false,
	publicKey: undefined as Hex | undefined,
}));
vi.mock("viem/account-abstraction", async (importOriginal) => {
	const original =
		await importOriginal<typeof import("viem/account-abstraction")>();
	return {
		...original,
		createWebAuthnCredential: async (
			...args: Parameters<typeof original.createWebAuthnCredential>
		) => {
			const credential = await original.createWebAuthnCredential(...args);
			created.publicKey = credential.publicKey;
			if (!created.tamper) return credential;
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
	created.tamper = false;
	created.publicKey = undefined;
});
afterEach(() => {
	mock.uninstall();
});

/** A wallet-api whose fill step echoes the key `echo` picks from the key the device created. */
function buildApi(
	echo: (createdKey: { x: Hex; y: Hex }) => { x: Hex; y: Hex },
) {
	const claimPendingAddition = vi.fn(async () => ({
		rpId: "localhost",
		challenge: toBase64Url(new Uint8Array(32).fill(7)),
		pendingAdditionId: "slot-1",
	}));
	const fillPendingAddition = vi.fn(async () => ({
		ok: true as const,
		publicKey: echo(parseP256PublicKey(created.publicKey as Hex)),
	}));
	const api = {
		claimPendingAddition,
		fillPendingAddition,
	} as unknown as WalletManagementApi;
	return { api, fillPendingAddition };
}

const deposit = (api: WalletManagementApi) =>
	depositPasskeyIntoPendingAddition({
		api,
		claimCode: "CLAIM-CODE",
		userId: new Uint8Array(32).fill(1),
		userName: "Giano",
	});

describe("depositPasskeyIntoPendingAddition", () => {
	it("returns the key this device created and its fingerprint when wallet-api echoes the same key", async () => {
		// Upper-case hex: the same key in another spelling still matches.
		const { api, fillPendingAddition } = buildApi((key) => ({
			x: `0x${key.x.slice(2).toUpperCase()}` as Hex,
			y: `0x${key.y.slice(2).toUpperCase()}` as Hex,
		}));

		const deposited = await deposit(api);

		const local = parseP256PublicKey(created.publicKey as Hex);
		expect(fillPendingAddition).toHaveBeenCalledOnce();
		expect(deposited.publicKey).toEqual(local);
		expect(deposited.fingerprint).toBe(
			ownerFingerprint(publicKeyOwnerBytes(local.x, local.y)),
		);
	});

	it("refuses a key that wallet-api reports differently from the one this device created", async () => {
		// The backend stored another key: here, the device's key with x replaced.
		const { api } = buildApi((key) => ({
			x: pad("0x01", { size: 32 }),
			y: key.y,
		}));

		await expect(deposit(api)).rejects.toBeInstanceOf(
			PendingAdditionKeyMismatchError,
		);
	});

	it("rejects a malformed key before it is deposited", async () => {
		created.tamper = true;
		const { api, fillPendingAddition } = buildApi((key) => key);

		await expect(deposit(api)).rejects.toBeInstanceOf(
			InvalidP256PublicKeyError,
		);
		expect(fillPendingAddition).not.toHaveBeenCalled();
	});
});
