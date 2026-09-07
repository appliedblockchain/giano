import { ulid } from 'ulid';
import { TransportRpcError } from './errors';
import { PROTOCOL_VERSION, RPC_ERRORS, parseTransportMessage, type TransportMessage } from './protocol';

export type RequestContext = {
  /** The pinned dApp origin — show it on every consent screen. */
  dappOrigin: string;
  sdkVersion: string;
};

export type RequestHandler = (method: string, params: unknown, context: RequestContext) => Promise<unknown>;

export type TransportHostOptions = {
  walletVersion?: string;
  capabilities?: string[];
  /**
   * Origins allowed to connect. Empty list (or unset) = NO origin may connect —
   * the host fails closed. The literal entry '*' allows any origin (dev only; it
   * must be typed deliberately). wallet-web populates this from its runtime config
   * `allowedDappOrigins`.
   */
  allowedOrigins?: string[];
  onRequest: RequestHandler;
  /** The popup window (overridable in tests). */
  hostWindow?: Window;
  onConnected?: (context: RequestContext) => void;
  onClosed?: () => void;
};

/**
 * Wallet side of the popup transport. Pins the FIRST validated dApp origin+source per
 * popup lifetime: after the handshake, messages from any other origin or window are
 * silently ignored, and every outgoing message targets the pinned origin explicitly.
 */
export class TransportHost {
  private readonly options: TransportHostOptions;
  private readonly hostWindow: Window;
  private pinnedOrigin: string | null = null;
  private pinnedSource: MessageEventSource | null = null;
  private sdkVersion = 'unknown';
  private started = false;
  private readonly onMessage = (event: MessageEvent) => void this.handleMessage(event);

  constructor(options: TransportHostOptions) {
    this.options = options;
    this.hostWindow = options.hostWindow ?? window;
  }

  get dappOrigin(): string | null {
    return this.pinnedOrigin;
  }

  /** Attach listeners and announce readiness to the opener. */
  start(): void {
    if (this.started) return;
    this.started = true;
    this.hostWindow.addEventListener('message', this.onMessage);
    // `ready` carries no data and is the only message sent before an origin is pinned;
    // '*' is safe here and unavoidable (the opener's origin is unknown until handshake).
    this.hostWindow.opener?.postMessage({ giano: PROTOCOL_VERSION, id: ulid(), type: 'ready' }, '*');
  }

  stop(): void {
    this.hostWindow.removeEventListener('message', this.onMessage);
    this.started = false;
  }

  sendEvent(event: string, data?: unknown): void {
    this.post({ giano: PROTOCOL_VERSION, id: ulid(), type: 'event', payload: { event, data } });
  }

  /** Announce teardown to the dApp (e.g. before the popup closes itself). */
  close(): void {
    this.post({ giano: PROTOCOL_VERSION, id: ulid(), type: 'close' });
    this.stop();
    this.options.onClosed?.();
  }

  private post(message: TransportMessage): void {
    if (!this.pinnedOrigin || !this.pinnedSource) return;
    (this.pinnedSource as Window).postMessage(message, { targetOrigin: this.pinnedOrigin });
  }

  private isAllowedOrigin(origin: string): boolean {
    const allowed = this.options.allowedOrigins ?? [];
    if (allowed.includes('*')) return true; // explicit dev escape hatch — never the default
    return allowed.includes(origin);
  }

  private async handleMessage(event: MessageEvent): Promise<void> {
    const message = parseTransportMessage(event.data);
    if (!message) return;

    if (message.type === 'handshake') {
      // first validated handshake pins origin + source for the popup's lifetime
      if (this.pinnedOrigin) {
        if (event.origin !== this.pinnedOrigin || event.source !== this.pinnedSource) return;
      } else {
        if (!event.source || !this.isAllowedOrigin(event.origin)) {
          // The drop stays silent on the wire — but not in the wallet's own console. Without
          // this, a misconfigured allow-list is indistinguishable from a severed opener: both
          // surface on the dApp as the same 15s HANDSHAKE_TIMEOUT.
          console.warn(
            `[giano] handshake refused: origin ${event.origin} is not in allowedDappOrigins (${JSON.stringify(this.options.allowedOrigins ?? [])})`,
          );
          return;
        }
        this.pinnedOrigin = event.origin;
        this.pinnedSource = event.source;
      }
      this.sdkVersion = message.payload.sdkVersion;
      this.post({
        giano: PROTOCOL_VERSION,
        id: message.id,
        type: 'handshake:ack',
        payload: { walletVersion: this.options.walletVersion ?? '0.0.0', capabilities: this.options.capabilities ?? [] },
      });
      this.options.onConnected?.({ dappOrigin: this.pinnedOrigin!, sdkVersion: this.sdkVersion });
      return;
    }

    // everything else requires the pinned channel
    if (!this.pinnedOrigin || event.origin !== this.pinnedOrigin || event.source !== this.pinnedSource) return;

    if (message.type === 'rpc') {
      try {
        const result = await this.options.onRequest(message.payload.method, message.payload.params, {
          dappOrigin: this.pinnedOrigin,
          sdkVersion: this.sdkVersion,
        });
        this.post({ giano: PROTOCOL_VERSION, id: message.id, type: 'rpc:response', payload: { result } });
      } catch (error) {
        const rpcError =
          error instanceof TransportRpcError
            ? { code: error.code, message: error.message, data: error.data }
            : { code: RPC_ERRORS.INTERNAL, message: error instanceof Error ? error.message : 'internal error' };
        this.post({ giano: PROTOCOL_VERSION, id: message.id, type: 'rpc:response', payload: { error: rpcError } });
      }
      return;
    }

    if (message.type === 'close') {
      this.stop();
      this.options.onClosed?.();
    }
  }
}
