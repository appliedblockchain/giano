import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";
import {
	startTestStack,
	stopTestStack,
	TENANT_A,
	type TestContext,
} from "./setup.js";

/**
 * The ceremony rate limit is keyed on tenant + request.ip. Behind the ALB or the wallet UI's nginx,
 * request.ip is the client only when TRUST_PROXY names those proxies; otherwise every user shares
 * the proxy's address and one client can exhaust the limit for the whole tenant.
 */
describe("TRUST_PROXY", () => {
	const baseEnv = {
		NODE_ENV: "test",
		GIANO_DEPLOYMENT_CLASS: "development",
		GIANO_ENVIRONMENT: "test",
		DATABASE_URL: "postgres://u:p@localhost:5432/db",
		CHAIN_ID: "31337",
		RPC_URL: "http://localhost:8545",
		BUNDLER_URL: "http://localhost:4337",
		ENTRYPOINT_ADDRESS: "0x433709009B8330FDa32311DF1C2AFA402eD8D009",
		FACTORY_ADDRESS: "0x2222222222222222222222222222222222222222",
	};
	const trustProxy = (value?: string) =>
		loadConfig({
			...baseEnv,
			...(value === undefined ? {} : { TRUST_PROXY: value }),
		} as NodeJS.ProcessEnv).TRUST_PROXY;

	it("trusts no proxy when unset or empty", () => {
		expect(trustProxy()).toBe(false);
		expect(trustProxy("")).toBe(false);
	});

	it("accepts IPs, CIDRs and named ranges", () => {
		expect(trustProxy("10.40.0.0/16, 127.0.0.1,fd00::/8,uniquelocal")).toEqual([
			"10.40.0.0/16",
			"127.0.0.1",
			"fd00::/8",
			"uniquelocal",
		]);
	});

	it("refuses `true`, a hop count and malformed entries", () => {
		expect(() => trustProxy("true")).toThrow(/would trust every peer/);
		expect(() => trustProxy("2")).toThrow(/TRUST_PROXY/);
		expect(() => trustProxy("10.40.0.0/33")).toThrow(/TRUST_PROXY/);
		expect(() => trustProxy("10.40.0.0/16,proxy.local")).toThrow(
			/proxy\.local/,
		);
	});
});

describe("per-IP rate limits behind a trusted proxy", () => {
	const LIMIT = 2;
	const PROXY = "10.40.1.5";
	let ctx: TestContext;

	beforeAll(async () => {
		ctx = await startTestStack({
			CEREMONY_RATE_LIMIT_PER_MINUTE: String(LIMIT),
			USEROP_RECEIPT_RATE_LIMIT_PER_MINUTE: String(LIMIT),
			TRUST_PROXY: "10.40.0.0/16",
		});
	}, 120_000);

	// The public receipt lookup is keyed on request.ip alone (it has no tenant). Without a trusted
	// proxy, one client polling hard would use the budget of every dApp's receipt wait.
	it("gives each client its own receipt-lookup budget", async () => {
		const receipt = (forwardedFor: string) =>
			ctx.app
				.inject({
					method: "GET",
					url: `/v1/userops/0x${"ab".repeat(32)}/receipt`,
					remoteAddress: PROXY,
					headers: { "x-forwarded-for": forwardedFor },
				})
				.then((res) => res.statusCode);

		const flooder = [];
		for (let i = 0; i <= LIMIT; i++) {
			flooder.push(await receipt("198.51.100.20"));
		}
		expect(flooder).toEqual([200, 200, 429]);

		// Same proxy, another client: its receipt wait is unaffected.
		expect(await receipt("198.51.100.21")).toBe(200);
	});

	afterAll(async () => {
		if (ctx) await stopTestStack(ctx);
	});

	const options = (remoteAddress: string, forwardedFor?: string) =>
		ctx.app
			.inject({
				method: "POST",
				url: "/v1/webauthn/options",
				remoteAddress,
				headers: {
					origin: TENANT_A.walletOrigin,
					...(forwardedFor ? { "x-forwarded-for": forwardedFor } : {}),
				},
				payload: { externalUserId: "trust-proxy-user" },
			})
			.then((res) => res.statusCode);

	it("gives each client behind the proxy its own budget", async () => {
		const attacker = [];
		for (let i = 0; i <= LIMIT; i++) {
			attacker.push(await options(PROXY, "198.51.100.1"));
		}
		expect(attacker).toEqual([200, 200, 429]);

		// Same tenant, same proxy, another client: not locked out.
		expect(await options(PROXY, "198.51.100.2")).toBe(200);
	});

	it("takes the address the proxy saw, not one the client wrote into the header", async () => {
		// The client prepends a fresh address each time; the proxy appends the real one last.
		const codes = [];
		for (let i = 0; i <= LIMIT; i++) {
			codes.push(await options(PROXY, `192.0.2.${i + 1}, 198.51.100.3`));
		}
		expect(codes).toEqual([200, 200, 429]);
	});

	it("ignores X-Forwarded-For from a peer that is not a trusted proxy", async () => {
		const codes = [];
		for (let i = 0; i <= LIMIT; i++) {
			codes.push(await options("203.0.113.9", `192.0.2.${i + 10}`));
		}
		expect(codes).toEqual([200, 200, 429]);
	});
});
