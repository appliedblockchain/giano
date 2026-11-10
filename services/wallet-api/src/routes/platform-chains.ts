import { inArray } from "drizzle-orm";
import type { FastifyInstance, FastifyRequest } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { hexToBigInt } from "viem";
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
	/**
	 * The last full verification (boot or recovery); null until one has run. Each failure is its
	 * kind only: a failure's detail can hold the node's URL, and a provider key in it.
	 */
	verification: z
		.object({
			checkedAt: z.string(),
			failures: z.array(z.object({ kind: z.string() })),
		})
		.nullable(),
	/**
	 * The prober's last reachability probe; null until one has run. `detail` is a category
	 * (`timeout`, `http 429`, `connection refused`…), never an error's message.
	 */
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
		/** The chain's gas price as the bundler sees it; null where executors are unknown. */
		gasPriceWei: z.string().nullable(),
		/**
		 * Why the executors are null: `unsupported`, the bundler does not have the method (Alto, or a
		 * giano-bundler older than B7); `unavailable`, it did not answer in time or its node failed,
		 * or the answer was not the expected shape. Null where they are known.
		 */
		executorsUnknown: z.enum(["unsupported", "unavailable"]).nullable(),
		/** How long a lane may hold one transaction before it is stuck; null where unknown. */
		laneStuckAfterSeconds: z.number().int().nullable(),
		/**
		 * The keys that sign and pay for each handleOps transaction (B7); null where the bundler does
		 * not report them. An executor out of funds stops submission through it.
		 */
		executors: z
			.array(
				z.object({
					address: z.string(),
					balanceWei: z.string(),
					/** Its lane holds a transaction in flight. */
					busy: z.boolean(),
					/** When the lane took the transaction it holds; null while idle. */
					busySince: z.string().nullable(),
					/**
					 * How long the lane has held it, by the bundler's own clock; null while idle or from a
					 * bundler that predates it. The stuck check uses this, not a reader's clock.
					 */
					heldSeconds: z.number().int().nonnegative().nullable(),
					latestNonce: z.number().int(),
					pendingNonce: z.number().int(),
				}),
			)
			.nullable(),
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

/**
 * The bundler's executor lanes in decimal, or unknown: an answer that is not the expected shape is
 * reported as unknown rather than failing every chain's status.
 */
const quantity = z.string().regex(/^0x[0-9a-fA-F]+$/);
/** giano-bundler's `giano_executors` answer, checked: anything else is not used. */
const lanesSchema = z.object({
	gasPriceWei: quantity,
	laneStuckAfterSeconds: quantity.optional(),
	executors: z.array(
		z.object({
			address: z.string().regex(/^0x[0-9a-fA-F]{40}$/),
			balanceWei: quantity,
			busy: z.boolean(),
			busySince: quantity.nullable().optional(),
			heldSeconds: quantity.nullable().optional(),
			latestNonce: quantity,
			pendingNonce: quantity,
		}),
	),
});

type Lanes = { answer: unknown } | { unknown: "unsupported" | "unavailable" };

function executorsOf(
	lanes: Lanes | undefined,
): Pick<
	ChainStatus["bundler"],
	"gasPriceWei" | "executors" | "executorsUnknown" | "laneStuckAfterSeconds"
> {
	const unknown = (why: "unsupported" | "unavailable") => ({
		gasPriceWei: null,
		executors: null,
		executorsUnknown: why,
		laneStuckAfterSeconds: null,
	});
	if (!lanes) return unknown("unavailable");
	if ("unknown" in lanes) return unknown(lanes.unknown);
	// A wrong shape is unknown for this chain, never a response that fails for every chain.
	const parsed = lanesSchema.safeParse(lanes.answer);
	if (!parsed.success) return unknown("unavailable");
	const { data } = parsed;
	return {
		gasPriceWei: BigInt(data.gasPriceWei).toString(),
		executorsUnknown: null,
		laneStuckAfterSeconds:
			data.laneStuckAfterSeconds === undefined
				? null
				: Number(BigInt(data.laneStuckAfterSeconds)),
		executors: data.executors.map((lane) => ({
			address: lane.address,
			balanceWei: BigInt(lane.balanceWei).toString(),
			busy: lane.busy,
			busySince: lane.busySince
				? new Date(Number(BigInt(lane.busySince)) * 1000).toISOString()
				: null,
			heldSeconds: lane.heldSeconds ? Number(BigInt(lane.heldSeconds)) : null,
			latestNonce: Number(BigInt(lane.latestNonce)),
			pendingNonce: Number(BigInt(lane.pendingNonce)),
		})),
	};
}

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
		ledgers: Promise<Map<number, typeof paymasterState.$inferSelect>>,
	): Promise<ChainStatus> {
		const [head, entryPoints, lanes, byChain] = await Promise.all([
			// One attempt, no retries: `within` bounds the wait, this bounds the request (viem's
			// transport would otherwise retry a dead node for some 30 s, per admin with Health open).
			within(
				chain.publicClient
					.request(
						{ method: "eth_getBlockByNumber", params: ["latest", false] },
						{ retryCount: 0 },
					)
					.then((block) =>
						block
							? {
									number: hexToBigInt(block.number as `0x${string}`),
									timestamp: hexToBigInt(block.timestamp),
								}
							: undefined,
					),
				timeout,
			),
			// A JSON-RPC error is an answer: the bundler is up, and cannot say what it supports.
			// The signal ends the request itself, so a bundler that never answers holds no socket.
			within(
				chain.bundler
					.supportedEntryPoints(AbortSignal.timeout(timeout))
					.catch((error: unknown) =>
						error instanceof BundlerRpcError
							? ("refused" as const)
							: Promise.reject(error),
					),
				timeout,
			),
			// Unknown, not a failure, where the bundler cannot say: method-not-found is a bundler
			// without it (Alto, or one older than B7); anything else, its node or the time budget.
			within(
				chain.bundler.executors(AbortSignal.timeout(timeout)).then(
					(answer): Lanes => ({ answer }),
					(error: unknown): Lanes => ({
						unknown:
							error instanceof BundlerRpcError && error.code === -32601
								? "unsupported"
								: "unavailable",
					}),
				),
				timeout,
			),
			ledgers,
		]);
		const ledger = byChain.get(chain.chainId);
		const headBlock = head?.number ?? null;
		const lastSynced = ledger?.lastSyncedBlock ?? null;
		return {
			chainId: chain.chainId,
			name: chain.descriptor.name,
			registryStatus: chain.status,
			verification: chain.verification
				? {
						checkedAt: chain.verification.checkedAt.toISOString(),
						failures: chain.verification.failures.map((failure) => ({
							kind: failure.kind,
						})),
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
				...executorsOf(lanes),
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
						/**
						 * The ledger lag past which wallet-api stops trusting the ledger
						 * (TENANT_DELETE_MAX_LEDGER_LAG_BLOCKS): the console warns from it, so the two agree.
						 */
						maxLedgerLagBlocks: z.number().int(),
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
			// Everything at once: a slow signer and a dead node each use their timeout side by side,
			// not one after the other. Each chain takes its ledger row when the query lands.
			const ledgers = (
				sponsoring.length > 0
					? opts.db
							.select()
							.from(paymasterState)
							.where(inArray(paymasterState.chainId, sponsoring))
					: Promise.resolve([])
			).then((rows) => new Map(rows.map((row) => [row.chainId, row])));
			const [signer, chains] = await Promise.all([
				opts.signerHealth
					? within(opts.signerHealth(), timeout).then(
							(health) => health ?? "unavailable",
						)
					: Promise.resolve("disabled" as const),
				Promise.all(opts.registry.all.map((chain) => statusOf(chain, ledgers))),
			]);
			return {
				signer,
				maxLedgerLagBlocks: opts.config.TENANT_DELETE_MAX_LEDGER_LAG_BLOCKS,
				chains,
			};
		},
	);
}
