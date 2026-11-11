/**
 * How wallet-api POSTs JSON-RPC to an upstream it does not control: the bundler and each chain's
 * node (G37). Every exchange is bounded twice.
 *
 * - Time: the whole exchange, headers AND body, must finish within `timeoutMs`. The deadline also
 *   aborts the request, so a hanging upstream releases its socket, not only the caller.
 * - Size: the body may not exceed `maxBytes`. A body that declares a larger length is refused before
 *   it is read. Any other body is read in chunks and cancelled as soon as it passes the limit, so an
 *   oversized answer is never held in memory whole.
 */

export type UpstreamLimits = {
	/** The longest one exchange with the upstream may take, headers and body together. */
	timeoutMs: number;
	/** The largest response body accepted, in bytes. */
	maxBytes: number;
};

export type UpstreamLimitReason = "timeout" | "too-large";

/**
 * An upstream exchange that hit one of its limits. The message names the upstream and the limit,
 * never its URL: an RPC URL can carry a provider key.
 */
export class UpstreamLimitError extends Error {
	constructor(
		public readonly reason: UpstreamLimitReason,
		public readonly upstream: string,
		message: string,
	) {
		super(message);
		this.name = "UpstreamLimitError";
	}
}

export type PostJsonRpcOptions = {
	/** Names the upstream in errors ("bundler", "node"). Never its URL. */
	upstream: string;
	limits: UpstreamLimits;
	fetchImpl: typeof fetch;
	/**
	 * The caller's own bound, if any. It aborts the request as well, but the limits still apply:
	 * whichever ends first wins.
	 */
	signal?: AbortSignal;
};

/**
 * POSTs `payload` as JSON and returns the parsed response body. Throws `UpstreamLimitError` when a
 * limit is hit, and a plain `Error` naming the status when the upstream answers with a non-2xx code.
 */
export async function postJsonRpc(
	url: string,
	payload: unknown,
	{ upstream, limits, fetchImpl, signal }: PostJsonRpcOptions,
): Promise<unknown> {
	const controller = new AbortController();
	let timer: ReturnType<typeof setTimeout> | undefined;
	// Raced as well as passed as the signal: a fetch implementation that ignores its signal (a test
	// double, or a stuck body stream) still cannot hold the caller past the deadline.
	const deadline = new Promise<never>((_, reject) => {
		timer = setTimeout(() => {
			const error = new UpstreamLimitError(
				"timeout",
				upstream,
				`${upstream} did not answer within ${limits.timeoutMs} ms`,
			);
			controller.abort(error);
			reject(error);
		}, limits.timeoutMs);
	});

	const exchange = async () => {
		const response = await fetchImpl(url, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(payload),
			signal: signal
				? AbortSignal.any([controller.signal, signal])
				: controller.signal,
		});
		if (!response.ok) {
			// Not read: the status is the whole answer, and the body could be any size.
			await response.body?.cancel().catch(() => {});
			throw new Error(`${capitalise(upstream)} HTTP ${response.status}`);
		}
		return JSON.parse(await readBounded(response, upstream, limits.maxBytes));
	};

	try {
		return await Promise.race([exchange(), deadline]);
	} finally {
		clearTimeout(timer);
	}
}

async function readBounded(
	response: Response,
	upstream: string,
	maxBytes: number,
): Promise<string> {
	const tooLarge = () =>
		new UpstreamLimitError(
			"too-large",
			upstream,
			`${upstream} response exceeded ${maxBytes} bytes`,
		);

	const declared = Number(response.headers.get("content-length"));
	if (declared > maxBytes) {
		await response.body?.cancel().catch(() => {});
		throw tooLarge();
	}
	if (!response.body) return "";

	const reader = response.body.getReader();
	const chunks: Uint8Array[] = [];
	let total = 0;
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		total += value.byteLength;
		if (total > maxBytes) {
			await reader.cancel().catch(() => {});
			throw tooLarge();
		}
		chunks.push(value);
	}
	return Buffer.concat(chunks, total).toString("utf8");
}

const capitalise = (word: string) =>
	word.charAt(0).toUpperCase() + word.slice(1);
