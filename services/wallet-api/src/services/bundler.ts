import type { Address } from 'viem';

/**
 * Minimal JSON-RPC client for the ERC-4337 bundler. The EntryPoint address is ALWAYS
 * the server-configured one — never anything from a request body.
 */
export function createBundlerService(bundlerUrl: string, entryPoint: Address, fetchImpl: typeof fetch = fetch) {
  let rpcId = 0;

  async function rpc<T>(method: string, params: unknown[]): Promise<T> {
    const response = await fetchImpl(bundlerUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params }),
    });
    if (!response.ok) {
      throw new Error(`Bundler HTTP ${response.status}`);
    }
    const body = (await response.json()) as { result?: T; error?: { code: number; message: string } };
    if (body.error) {
      throw new BundlerRpcError(body.error.code, body.error.message);
    }
    return body.result as T;
  }

  return {
    entryPoint,
    /** rpcUserOp fields must already be hex-encoded (RpcUserOperation shape). */
    sendUserOperation: (rpcUserOp: Record<string, unknown>) =>
      rpc<string>('eth_sendUserOperation', [rpcUserOp, entryPoint]),
    getUserOperationReceipt: (hash: string) => rpc<Record<string, unknown> | null>('eth_getUserOperationReceipt', [hash]),
    getUserOperationByHash: (hash: string) => rpc<Record<string, unknown> | null>('eth_getUserOperationByHash', [hash]),
  };
}

export class BundlerRpcError extends Error {
  constructor(
    public readonly code: number,
    message: string,
  ) {
    super(message);
    this.name = 'BundlerRpcError';
  }
}

export type BundlerService = ReturnType<typeof createBundlerService>;
