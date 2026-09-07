import { afterEach, describe, expect, it, vi } from 'vitest';
import { TransportClient } from '../src/client';
import { TransportRpcError } from '../src/errors';
import { TransportHost } from '../src/host';
import { PopupManager } from '../src/popup-manager';
import { RPC_ERRORS, PROTOCOL_VERSION } from '../src/protocol';
import { createWindowPair, flush, FakeWindow } from './fake-windows';

const DAPP = 'https://dapp.example.com';
const WALLET = 'https://wallet.example.com';

function setup(options: { allowedOrigins?: string[]; onRequest?: (method: string, params: unknown) => Promise<unknown> } = {}) {
  const pair = createWindowPair(DAPP, WALLET);

  const popupManager = new PopupManager({
    url: `${WALLET}/connect`,
    parent: { open: () => pair.popupHandle as unknown as Window, screenX: 0, screenY: 0, innerWidth: 1440, innerHeight: 900 } as never,
  });

  const client = new TransportClient({
    walletUrl: `${WALLET}/connect`,
    sdkVersion: '1.0.0-test',
    listenWindow: pair.dappWindow as unknown as Window,
    popupManager,
    handshakeTimeoutMs: 500,
    requestTimeoutMs: 1_000,
  });

  const host = new TransportHost({
    walletVersion: '2.0.0-test',
    allowedOrigins: options.allowedOrigins ?? [DAPP],
    onRequest: options.onRequest ?? (async (method) => `handled:${method}`),
    hostWindow: pair.hostWindow as unknown as Window,
  });

  const connect = async () => {
    const connected = client.connect();
    host.start(); // popup "loads" and announces ready
    await connected;
  };

  return { pair, client, host, connect };
}

afterEach(() => {
  vi.useRealTimers();
});

describe('handshake', () => {
  it('completes ready → handshake → ack and pins the dApp origin', async () => {
    const { client, host, connect } = setup();
    await connect();
    expect(client.isConnected).toBe(true);
    expect(host.dappOrigin).toBe(DAPP);
  });

  it('rejects connect on handshake timeout (e.g. COOP severed opener)', async () => {
    const { client } = setup();
    // host never starts — no ready ever arrives
    await expect(client.connect()).rejects.toMatchObject({ code: 'HANDSHAKE_TIMEOUT' });
  });

  it('ignores handshakes from origins not in the allowlist', async () => {
    const { client, host, connect } = setup({ allowedOrigins: ['https://only-this.example.com'] });
    await expect(connect()).rejects.toMatchObject({ code: 'HANDSHAKE_TIMEOUT' });
    expect(host.dappOrigin).toBeNull();
    expect(client.isConnected).toBe(false);
  });

  it('fails closed: an empty allowlist rejects every handshake', async () => {
    const { client, host, connect } = setup({ allowedOrigins: [] });
    await expect(connect()).rejects.toMatchObject({ code: 'HANDSHAKE_TIMEOUT' });
    expect(host.dappOrigin).toBeNull();
    expect(client.isConnected).toBe(false);
  });

  it("the explicit '*' entry allows any origin (dev escape hatch)", async () => {
    const { client, host, connect } = setup({ allowedOrigins: ['*'] });
    await connect();
    expect(client.isConnected).toBe(true);
    expect(host.dappOrigin).toBe(DAPP);
  });
});

describe('rpc', () => {
  it('round-trips a request and response', async () => {
    const { client, connect } = setup({
      onRequest: async (method, params) => ({ echo: { method, params } }),
    });
    await connect();
    const result = await client.request('eth_accounts', ['a', 1]);
    expect(result).toEqual({ echo: { method: 'eth_accounts', params: ['a', 1] } });
  });

  it('relays EIP-1193 errors (4001 user rejected)', async () => {
    const { client, connect } = setup({
      onRequest: async () => {
        throw new TransportRpcError(RPC_ERRORS.USER_REJECTED, 'User rejected the request');
      },
    });
    await connect();
    await expect(client.request('eth_sendTransaction', [{}])).rejects.toMatchObject({
      name: 'TransportRpcError',
      code: 4001,
      message: 'User rejected the request',
    });
  });

  it('maps unexpected handler failures to internal errors', async () => {
    const { client, connect } = setup({
      onRequest: async () => {
        throw new Error('boom');
      },
    });
    await connect();
    await expect(client.request('eth_chainId')).rejects.toMatchObject({ code: RPC_ERRORS.INTERNAL });
  });

  it('throws NOT_CONNECTED before connect', async () => {
    const { client } = setup();
    await expect(client.request('eth_chainId')).rejects.toMatchObject({ code: 'NOT_CONNECTED' });
  });
});

describe('events', () => {
  it('delivers wallet events to subscribed handlers', async () => {
    const { client, host, connect } = setup();
    await connect();
    const seen: unknown[] = [];
    client.on('accountsChanged', (data) => seen.push(data));
    host.sendEvent('accountsChanged', ['0xabc']);
    await flush();
    expect(seen).toEqual([['0xabc']]);
  });
});

describe('hostile messages', () => {
  it('host ignores rpc from a non-pinned origin/window', async () => {
    const { pair, client, host, connect } = setup({
      onRequest: async () => 'should-not-leak',
    });
    await connect();

    // attacker window injects a valid-looking rpc from a different origin
    const attacker = new FakeWindow('https://evil.example.com');
    pair.popupWindow.receive(
      { giano: PROTOCOL_VERSION, id: '01ATTACKERMSG0000000000000', type: 'rpc', payload: { method: 'eth_accounts' } },
      attacker,
    );
    await flush();

    // and a spoofed handshake cannot re-pin the origin
    pair.popupWindow.receive(
      { giano: PROTOCOL_VERSION, id: '01ATTACKERMSG0000000000001', type: 'handshake', payload: { sdkVersion: 'x', capabilities: [] } },
      attacker,
    );
    await flush();
    expect(host.dappOrigin).toBe(DAPP);
    expect(client.isConnected).toBe(true);
  });

  it('client drops responses that do not come from the wallet origin', async () => {
    const { pair, client, connect } = setup({ onRequest: () => new Promise(() => {}) });
    await connect();
    const request = client.request('eth_chainId');

    // spoofed response from wrong origin — listener receives origin=evil
    const evil = new FakeWindow('https://evil.example.com');
    for (const listener of [...pair.dappWindow.listeners]) {
      listener({
        data: { giano: PROTOCOL_VERSION, id: 'x'.repeat(26), type: 'rpc:response', payload: { result: 'spoofed' } },
        origin: evil.origin,
        source: evil,
      });
    }
    await expect(request).rejects.toMatchObject({ code: 'REQUEST_TIMEOUT' });
  });

  it('drops malformed envelopes', async () => {
    const { pair, host, connect } = setup();
    await connect();
    pair.popupWindow.receive({ garbage: true }, pair.dappWindow);
    pair.popupWindow.receive({ giano: 999, id: 'short', type: 'rpc' }, pair.dappWindow);
    await flush();
    expect(host.dappOrigin).toBe(DAPP); // still healthy
  });
});

describe('teardown', () => {
  it('client disconnect notifies the host', async () => {
    let closed = false;
    const pairSetup = setup();
    pairSetup.host['options'].onClosed = () => (closed = true);
    await pairSetup.connect();
    pairSetup.client.disconnect();
    await flush();
    expect(closed).toBe(true);
    expect(pairSetup.client.isConnected).toBe(false);
  });

  it('pending requests reject when the popup closes', async () => {
    const { pair, client, connect } = setup({ onRequest: () => new Promise(() => {}) });
    await connect();
    const request = client.request('eth_sendTransaction', [{}]);
    pair.popupHandle.close();
    // popup close watcher polls every 400ms; attach the rejection handler immediately
    // (a detached sleep here used to surface as an unhandled rejection)
    await expect(request).rejects.toMatchObject({ code: 'POPUP_CLOSED' });
  });
});
