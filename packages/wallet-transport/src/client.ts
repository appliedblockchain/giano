import { ulid } from 'ulid';
import { TransportError, TransportRpcError } from './errors';
import { PopupManager } from './popup-manager';
import { PROTOCOL_VERSION, parseTransportMessage, type TransportMessage } from './protocol';

export type TransportClientOptions = {
  /** Full URL of the wallet page (e.g. https://wallet.clientapp.com/connect). */
  walletUrl: string;
  sdkVersion?: string;
  capabilities?: string[];
  /** ms to wait for the popup's ready+handshake:ack (default 15s). */
  handshakeTimeoutMs?: number;
  /** ms to wait for an rpc:response — user actions can be slow (default 5 min). */
  requestTimeoutMs?: number;
  /** The dApp window (overridable in tests). */
  listenWindow?: Window;
  popupManager?: PopupManager;
};

type EventHandler = (data: unknown) => void;

/**
 * dApp side of the popup transport. Origin discipline: outgoing messages always use an
 * explicit `targetOrigin` (the wallet origin), and incoming messages are dropped unless
 * `event.origin` is the wallet origin AND `event.source` is our popup window.
 */
export class TransportClient {
  readonly walletOrigin: string;
  private readonly options: Required<Pick<TransportClientOptions, 'sdkVersion' | 'capabilities' | 'handshakeTimeoutMs' | 'requestTimeoutMs'>>;
  private readonly listenWindow: Window;
  private readonly popupManager: PopupManager;
  private popup: Window | null = null;
  private connected = false;
  private connectPromise: Promise<void> | null = null;
  private readonly pending = new Map<string, { resolve: (value: unknown) => void; reject: (error: Error) => void; timer: ReturnType<typeof setTimeout> }>();
  private readonly eventHandlers = new Map<string, Set<EventHandler>>();
  private closeWatcher: ReturnType<typeof setInterval> | null = null;
  private readonly onMessage = (event: MessageEvent) => this.handleMessage(event);

  constructor(options: TransportClientOptions) {
    this.walletOrigin = new URL(options.walletUrl).origin;
    this.options = {
      sdkVersion: options.sdkVersion ?? '0.0.0',
      capabilities: options.capabilities ?? [],
      handshakeTimeoutMs: options.handshakeTimeoutMs ?? 15_000,
      requestTimeoutMs: options.requestTimeoutMs ?? 300_000,
    };
    this.listenWindow = options.listenWindow ?? window;
    this.popupManager = options.popupManager ?? new PopupManager({ url: options.walletUrl });
  }

  get isConnected(): boolean {
    return this.connected && !!this.popup && !this.popup.closed;
  }

  /** Must be called from a user gesture (popup). Resolves once the handshake is acked. */
  connect(): Promise<void> {
    if (this.isConnected) return Promise.resolve();
    if (this.connectPromise) return this.connectPromise;

    this.listenWindow.addEventListener('message', this.onMessage);
    this.popup = this.popupManager.open();
    this.watchPopupClosed();

    this.connectPromise = new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.connectPromise = null;
        reject(
          new TransportError(
            'HANDSHAKE_TIMEOUT',
            'wallet popup did not complete the handshake — if the dApp sends Cross-Origin-Opener-Policy: same-origin, window.opener is severed; use same-origin-allow-popups',
          ),
        );
      }, this.options.handshakeTimeoutMs);

      this.handshakeWaiter = { resolve, reject, timer };
    });
    return this.connectPromise;
  }

  private handshakeWaiter: { resolve: () => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> } | null = null;

  /** EIP-1193-style request over the popup channel. */
  async request<T = unknown>(method: string, params?: unknown): Promise<T> {
    if (!this.isConnected) {
      throw new TransportError('NOT_CONNECTED', 'transport is not connected — call connect() from a user gesture first');
    }
    const id = ulid();
    const message = { giano: PROTOCOL_VERSION, id, type: 'rpc' as const, payload: { method, params } };
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new TransportError('REQUEST_TIMEOUT', `no response for ${method} within ${this.options.requestTimeoutMs}ms`));
      }, this.options.requestTimeoutMs);
      this.pending.set(id, { resolve: resolve as (value: unknown) => void, reject, timer });
      this.post(message);
    });
  }

  on(event: string, handler: EventHandler): () => void {
    if (!this.eventHandlers.has(event)) this.eventHandlers.set(event, new Set());
    this.eventHandlers.get(event)!.add(handler);
    return () => this.eventHandlers.get(event)?.delete(handler);
  }

  disconnect(): void {
    if (this.popup && !this.popup.closed) {
      this.post({ giano: PROTOCOL_VERSION, id: ulid(), type: 'close' });
    }
    this.teardown(new TransportError('DISCONNECTED', 'disconnected'));
    this.popupManager.close();
  }

  /**
   * Closes the wallet popup after a completed interaction WITHOUT ending the session.
   * The teardown is reported as `POPUP_CLOSED`, which callers treat as benign — the
   * cached session survives and the next request re-opens the popup (and the wallet
   * silently restores the account). Used for the ephemeral-popup UX where the popup
   * closes itself once each connect/sign/transaction resolves.
   */
  dismissPopup(): void {
    if (!this.popup) return;
    this.popupManager.close();
    this.teardown(new TransportError('POPUP_CLOSED', 'wallet popup dismissed after the request completed'));
  }

  private post(message: TransportMessage): void {
    this.popup?.postMessage(message, this.walletOrigin);
  }

  private handleMessage(event: MessageEvent): void {
    if (event.origin !== this.walletOrigin) return;
    if (!this.popup || event.source !== this.popup) return;
    const message = parseTransportMessage(event.data);
    if (!message) return;

    switch (message.type) {
      case 'ready': {
        this.post({
          giano: PROTOCOL_VERSION,
          id: ulid(),
          type: 'handshake',
          payload: { sdkVersion: this.options.sdkVersion, capabilities: this.options.capabilities },
        });
        return;
      }
      case 'handshake:ack': {
        this.connected = true;
        this.connectPromise = null;
        if (this.handshakeWaiter) {
          clearTimeout(this.handshakeWaiter.timer);
          this.handshakeWaiter.resolve();
          this.handshakeWaiter = null;
        }
        return;
      }
      case 'rpc:response': {
        const waiter = this.pending.get(message.id);
        if (!waiter) return;
        this.pending.delete(message.id);
        clearTimeout(waiter.timer);
        if (message.payload.error) {
          waiter.reject(TransportRpcError.from(message.payload.error));
        } else {
          waiter.resolve(message.payload.result);
        }
        return;
      }
      case 'event': {
        this.eventHandlers.get(message.payload.event)?.forEach((handler) => handler(message.payload.data));
        return;
      }
      case 'close': {
        this.teardown(new TransportError('DISCONNECTED', 'wallet closed the session'));
        return;
      }
      default:
        return;
    }
  }

  private watchPopupClosed(): void {
    if (this.closeWatcher) clearInterval(this.closeWatcher);
    this.closeWatcher = setInterval(() => {
      if (this.popup?.closed) {
        this.teardown(new TransportError('POPUP_CLOSED', 'the wallet popup was closed'));
      }
    }, 400);
  }

  private teardown(error: Error): void {
    if (this.closeWatcher) {
      clearInterval(this.closeWatcher);
      this.closeWatcher = null;
    }
    this.listenWindow.removeEventListener('message', this.onMessage);
    const wasConnected = this.connected;
    this.connected = false;
    this.popup = null;
    this.connectPromise = null;
    if (this.handshakeWaiter) {
      clearTimeout(this.handshakeWaiter.timer);
      this.handshakeWaiter.reject(error);
      this.handshakeWaiter = null;
    }
    for (const [, waiter] of this.pending) {
      clearTimeout(waiter.timer);
      waiter.reject(error);
    }
    this.pending.clear();
    if (wasConnected) {
      this.eventHandlers.get('disconnect')?.forEach((handler) => handler(error));
    }
  }
}
