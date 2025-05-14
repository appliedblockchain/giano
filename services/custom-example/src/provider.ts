import type { EIP1193EventMap, EIP1193Provider } from 'viem';
import { type EIP1193RequestOptions } from 'viem/types/eip1193';

const provider: EIP1193Provider = {
  on<TE extends keyof EIP1193EventMap>(event: TE, listener: EIP1193EventMap[TE]): void {},
  removeListener<TE extends keyof EIP1193EventMap>(event: TE, listener: EIP1193EventMap[TE]): void {},
  request<rpcSchemaOverride, _parameters, _returnType>(args: _parameters, options: EIP1193RequestOptions | undefined): Promise<_returnType> {
    return Promise.resolve(undefined as unknown as _returnType);
  },
};
