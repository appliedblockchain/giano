/**
 * Minimal JSON-RPC client for a chain's node, used by the read relay. Kept separate from the
 * viem `publicClient` so that a wallet's request is forwarded verbatim — method, params and
 * the node's own error — rather than re-encoded.
 */
export function createNodeRpcService(rpcUrl: string, fetchImpl: typeof fetch = fetch) {
  let rpcId = 0;

  return {
    async call(method: string, params: unknown[]): Promise<unknown> {
      const response = await fetchImpl(rpcUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params }),
      });
      if (!response.ok) {
        throw new Error(`Node HTTP ${response.status}`);
      }
      const body = (await response.json()) as { result?: unknown; error?: { code: number; message: string; data?: unknown } };
      if (body.error) {
        throw new NodeRpcError(body.error.code, body.error.message, body.error.data);
      }
      return body.result;
    },
  };
}

export class NodeRpcError extends Error {
  constructor(
    public readonly code: number,
    message: string,
    public readonly data?: unknown,
  ) {
    super(message);
    this.name = 'NodeRpcError';
  }
}

export type NodeRpcService = ReturnType<typeof createNodeRpcService>;
