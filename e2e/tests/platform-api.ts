import * as http from "node:http";
import { expect } from "@playwright/test";
import { privateKeyToAccount } from "viem/accounts";
import { loopbackOf } from "../origins.mjs";

/**
 * wallet-api's platform tier, called server to server on its loopback port the way the console's
 * proxy does: no Origin, which platform admin routes refuse. For specs that set up state faster
 * than the console's UI could.
 */

/** anvil's account 3, bootstrapped as admin-e2e for the e2e environment (services/wallet-api/src/environments.ts). */
export const PLATFORM_ADMIN = privateKeyToAccount(
	"0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
);
const API = loopbackOf("api");

/** A raw request, so the Host header can name a tenant the way a browser on its origin would. */
export function platformCall(
	method: string,
	path: string,
	{
		body,
		headers = {},
	}: { body?: unknown; headers?: Record<string, string> } = {},
) {
	const url = new URL(path, API);
	const payload = body === undefined ? undefined : JSON.stringify(body);
	return new Promise<{ status: number; json: () => any }>((resolve, reject) => {
		const request = http.request(
			url,
			{
				method,
				headers: {
					...(payload ? { "content-type": "application/json" } : {}),
					...headers,
				},
			},
			(response) => {
				let text = "";
				response.on("data", (chunk) => (text += chunk));
				response.on("end", () =>
					resolve({
						status: response.statusCode ?? 0,
						json: () => JSON.parse(text),
					}),
				);
			},
		);
		request.on("error", reject);
		request.end(payload);
	});
}

/** A platform admin session for admin-e2e: its bearer token. */
export async function platformSignIn(): Promise<string> {
	const challenge = await platformCall("POST", "/v1/platform/auth/challenge", {
		body: { address: PLATFORM_ADMIN.address, chainId: 31337 },
	});
	expect(challenge.status).toBe(200);
	const { message } = challenge.json();
	const verify = await platformCall("POST", "/v1/platform/auth/verify", {
		body: {
			message,
			signature: await PLATFORM_ADMIN.signMessage({ message }),
		},
	});
	expect(verify.status).toBe(200);
	return verify.json().token;
}
