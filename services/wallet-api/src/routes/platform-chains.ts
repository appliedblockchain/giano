import { inArray } from "drizzle-orm";
import type { FastifyInstance, FastifyRequest } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { z } from "zod";
import type { AppConfig } from "../config.js";
import type { Db } from "../db/index.js";
import { paymasterState } from "../db/schema.js";
import { BundlerRpcError } from "../services/bundler.js";
import type { ChainRegistry, ChainServices } from "../services/chains.js";

/** Each part of a chain's status gets this long; a chain that takes longer is reported unreachable. */
export const CHAIN_STATUS_TIMEOUT_MS = 3_000;

const errorSchema = z
	.object({ error: z.string(), message: z.string() })
	.passthrough();

const chainSchema = z.object({
	chainId: z.number().int(),
	name: z.string(),
	/** The prober's verdict, as /v1/version reports it. */
	registryStatus: z.enum(["ready", "unavailable"]),
	/** The last full verification (boot or recovery); null until one has run. */
	verification: z
		.object({
			checkedAt: z.string(),
			failures: z.array(z.record(z.string(), z.unknown())),
		})
		.nullable(),
	/** The prober's last reachability probe; null until one has run. */
	lastProbe: z
		.object({
			at: z.string(),
			ok: z.boolean(),
			detail: z.string().optional(),
		})
		.nullable(),
	node: z.object({
		reachable: z.boolean(),
		headBlock: z.string().nullable(),
		headAgeSeconds: z.number().nullable(),
	}),
	bundler: z.object({
		reachable: z.boolean(),
		/** Whether the bundler itself lists the configured EntryPoint (eth_supportedEntryPoints). */
		entryPointSupported: z.boolean().nullable(),
	}),
	/** Null where this chain does not sponsor. */
	paymaster: z
		.object({
			address: z.string(),
			depositWei: z.string().nullable(),
			treasuryWei: z.string().nullable(),
			stakeWei: z.string().nullable(),
			invariantSlackWei: z.string().nullable(),
			lastSyncedBlock: z.string().nullable(),
			/** headBlock − lastSyncedBlock; null when either is unknown. */
			watcherLagBlocks: z.number().nullable(),
			checkedAt: z.string().nullable(),
		})
		.nullable(),
});

export type ChainStatus = z.infer<typeof chainSchema>;

/** `promise`, or `undefined` once `ms` has passed: a slow part is reported, never waited out. */
function within<T>(promise: Promise<T>, ms: number): Promise<T | undefined> {
	let timer: NodeJS.Timeout | undefined;
	return Promise.race([
		promise.catch(() => undefined),
		new Promise<undefined>((resolve) => {
			timer = setTimeout(() => resolve(undefined), ms);
		}),
	]).finally(() => clearTimeout(timer));
}

/**
 * The status of every chain this deployment serves (specs/PLATFORM-ADMIN-SPECS.md §10, B3): what
 * only wallet-api can see — the prober's verdict, the bundler behind its internal hostname, the
 * ledger's position — answering "can this deployment transact on chain X right now". No node or
 * bundler URL is ever in the response: they are internal, and some carry keys.
 *
 * The thresholds that make these figures a verdict (head age, watcher lag) are the console's,
 * beside giano-doctor's.
 */
export default async function platformChainRoutes(
	instance: FastifyInstance,
	opts: {
		db: Db;
		config: AppConfig;
		registry: ChainRegistry;
		/** The sponsorship signer's health; one signer serves every chain (MC-72). */
		signerHealth?: () => Promise<"ok" | "unavailable">;
		timeoutMs?: number;
	},
) {
	const app = instance.withTypeProvider<ZodTypeProvider>();
	app.addHook("onRequest", app.requirePlatformAdmin);
	const timeout = opts.timeoutMs ?? CHAIN_STATUS_TIMEOUT_MS;

	async function statusOf(
		chain: ChainServices,
		ledger: typeof paymasterState.$inferSelect | undefined,
	): Promise<ChainStatus> {
		const [head, entryPoints] = await Promise.all([
			within(chain.publicClient.getBlock({ blockTag: "latest" }), timeout),
			// A JSON-RPC error is an answer: the bundler is up, and cannot say what it supports.
			within(
				chain.bundler
					.supportedEntryPoints()
					.catch((error: unknown) =>
						error instanceof BundlerRpcError
							? ("refused" as const)
							: Promise.reject(error),
					),
				timeout,
			),
		]);
		const headBlock = head?.number ?? null;
		const lastSynced = ledger?.lastSyncedBlock ?? null;
		return {
			chainId: chain.chainId,
			name: chain.descriptor.name,
			registryStatus: chain.status,
			verification: chain.verification
				? {
						checkedAt: chain.verification.checkedAt.toISOString(),
						failures: chain.verification.failures,
					}
				: null,
			lastProbe: chain.lastProbe
				? {
						at: chain.lastProbe.at.toISOString(),
						ok: chain.lastProbe.ok,
						...(chain.lastProbe.detail
							? { detail: chain.lastProbe.detail }
							: {}),
					}
				: null,
			node: {
				reachable: head !== undefined,
				headBlock: headBlock?.toString() ?? null,
				headAgeSeconds: head
					? Math.max(0, Math.round(Date.now() / 1000 - Number(head.timestamp)))
					: null,
			},
			bundler: {
				reachable: entryPoints !== undefined,
				entryPointSupported: Array.isArray(entryPoints)
					? entryPoints.some(
							(address) =>
								address.toLowerCase() === chain.entryPoint.toLowerCase(),
						)
					: null,
			},
			paymaster: chain.paymaster
				? {
						address: chain.paymaster.address,
						depositWei: ledger?.depositWei ?? null,
						treasuryWei: ledger?.treasuryWei ?? null,
						stakeWei: ledger?.stakeWei ?? null,
						invariantSlackWei: ledger?.invariantSlackWei ?? null,
						lastSyncedBlock: lastSynced?.toString() ?? null,
						watcherLagBlocks:
							headBlock !== null && lastSynced !== null
								? Number(headBlock - lastSynced)
								: null,
						checkedAt: ledger?.checkedAt?.toISOString() ?? null,
					}
				: null,
		};
	}

	app.get(
		"/v1/platform/chains",
		{
			config: {
				rateLimit: {
					max: opts.config.PLATFORM_RATE_LIMIT_PER_MINUTE,
					timeWindow: "1 minute",
					keyGenerator: (request: FastifyRequest) =>
						`platform-session:${request.platformAdmin?.sessionId ?? "none"}`,
				},
			},
			schema: {
				tags: ["platform"],
				security: [{ platformSession: [] }],
				summary:
					"The status of every served chain, probed in parallel with a 3-second timeout each; never a node or bundler URL",
				response: {
					200: z.object({
						signer: z.enum(["ok", "unavailable", "disabled"]),
						chains: z.array(chainSchema),
					}),
					401: errorSchema,
				},
			},
		},
		async () => {
			const sponsoring = opts.registry.all
				.filter((chain) => chain.paymaster)
				.map((chain) => chain.chainId);
			const [signer, ledgers] = await Promise.all([
				opts.signerHealth
					? within(opts.signerHealth(), timeout).then(
							(health) => health ?? "unavailable",
						)
					: Promise.resolve("disabled" as const),
				sponsoring.length > 0
					? opts.db
							.select()
							.from(paymasterState)
							.where(inArray(paymasterState.chainId, sponsoring))
					: Promise.resolve([]),
			]);
			const byChain = new Map(ledgers.map((row) => [row.chainId, row]));
			const chains = await Promise.all(
				opts.registry.all.map((chain) =>
					statusOf(chain, byChain.get(chain.chainId)),
				),
			);
			return { signer, chains };
		},
	);
}
