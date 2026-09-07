import type { Hex } from 'viem';
import type { SmartAccount } from 'viem/account-abstraction';
import { describe, expect, it, vi } from 'vitest';
import {
  SmartAccountDeploymentError,
  WaitForSmartAccountDeploymentError,
  WaitForSmartAccountDeploymentTimeoutError,
  ensureSmartAccountIsDeployed,
  isSmartAccountDeployed,
  waitForSmartAccountDeployment,
} from '../src/account/deployment';
import { GianoError } from '../src/giano-error';
import { WALLET_ADDRESS, createMockClient } from './helpers';

const fakeAccount = { getAddress: async () => WALLET_ADDRESS } as unknown as SmartAccount;

describe('isSmartAccountDeployed', () => {
  it('is false for empty code and true for present bytecode', async () => {
    const { client: empty } = createMockClient({ code: '0x' });
    expect(await isSmartAccountDeployed(empty, fakeAccount)).toBe(false);

    const { client: deployed } = createMockClient({ code: '0x60016002' });
    expect(await isSmartAccountDeployed(deployed, fakeAccount)).toBe(true);
  });
});

describe('waitForSmartAccountDeployment', () => {
  it('resolves once bytecode appears', async () => {
    const { client } = createMockClient({ code: (i) => (i === 0 ? '0x' : '0xdeadbeef') });
    await expect(waitForSmartAccountDeployment(client, { smartAccount: fakeAccount, pollingInterval: 5 })).resolves.toBeUndefined();
  });

  it('rejects with a timeout error when never deployed', async () => {
    const { client } = createMockClient({ code: '0x' });
    await expect(
      waitForSmartAccountDeployment(client, { smartAccount: fakeAccount, pollingInterval: 5, timeout: 30 }),
    ).rejects.toBeInstanceOf(WaitForSmartAccountDeploymentTimeoutError);
  });

  it('rejects with a deployment error when the code check throws', async () => {
    const { client } = createMockClient({
      code: () => {
        throw new Error('rpc down');
      },
    });
    await expect(
      waitForSmartAccountDeployment(client, { smartAccount: fakeAccount, pollingInterval: 5 }),
    ).rejects.toBeInstanceOf(WaitForSmartAccountDeploymentError);
  });
});

describe('ensureSmartAccountIsDeployed', () => {
  it('returns immediately without sending a tx when already deployed', async () => {
    const { client } = createMockClient({ code: '0xabcd' });
    const sendTx = vi.fn(async () => `0x${'11'.repeat(32)}` as Hex);
    await ensureSmartAccountIsDeployed(fakeAccount, client, sendTx as never);
    expect(sendTx).not.toHaveBeenCalled();
  });

  it('sends a deployment tx then waits for bytecode', async () => {
    const { client } = createMockClient({ code: (i) => (i === 0 ? '0x' : '0xabcd') });
    const sendTx = vi.fn(async (_params: unknown) => `0x${'11'.repeat(32)}` as Hex);
    await ensureSmartAccountIsDeployed(fakeAccount, client, sendTx as never);
    expect(sendTx).toHaveBeenCalledOnce();
    expect(sendTx.mock.calls[0][0]).toEqual([{ to: WALLET_ADDRESS, value: '0x0', data: '0x' }]);
  });

  it('wraps unexpected failures in SmartAccountDeploymentError with the cause attached', async () => {
    const { client } = createMockClient({
      code: () => {
        throw new Error('rpc down');
      },
    });
    const sendTx = vi.fn(async () => `0x${'11'.repeat(32)}` as Hex);
    const error = await ensureSmartAccountIsDeployed(fakeAccount, client, sendTx as never).catch((e) => e);
    expect(error).toBeInstanceOf(SmartAccountDeploymentError);
    expect((error as SmartAccountDeploymentError).cause).toBeInstanceOf(Error);
  });

  it('re-throws a WaitForSmartAccountDeploymentError unchanged', async () => {
    let sends = 0;
    const { client } = createMockClient({
      code: (i) => {
        if (i === 0) return '0x'; // not deployed → triggers send + wait
        throw new Error('boom during wait');
      },
    });
    const sendTx = vi.fn(async () => {
      sends += 1;
      return `0x${'11'.repeat(32)}` as Hex;
    });
    await expect(ensureSmartAccountIsDeployed(fakeAccount, client, sendTx as never)).rejects.toBeInstanceOf(WaitForSmartAccountDeploymentError);
    expect(sends).toBe(1);
  });
});

describe('deployment error types', () => {
  it('form a GianoError instanceof chain and carry the timeout', () => {
    const timeout = new WaitForSmartAccountDeploymentTimeoutError(5000);
    expect(timeout).toBeInstanceOf(GianoError);
    expect(timeout).toBeInstanceOf(SmartAccountDeploymentError);
    expect(timeout).toBeInstanceOf(WaitForSmartAccountDeploymentError);
    expect(timeout.timeout).toBe(5000);
    expect(timeout.message).toMatch(/5000ms/);
    expect(timeout.name).toBe('WaitForSmartAccountDeploymentTimeoutError');
  });
});
