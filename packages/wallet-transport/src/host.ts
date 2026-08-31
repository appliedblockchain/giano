import { ulid } from 'ulid';
import { TransportRpcError } from './errors';
import { PROTOCOL_VERSION, RPC_ERRORS, parseTransportMessage, type HandshakeNackReason, type TransportMessage } from './protocol';

export type RequestContext = {
  /** The pinned dApp origin — show it on every consent screen. */
  dappOrigin: string;
  sdkVersion: string;
  /**
   * The chain GRANTED for this transport session, negotiated in the handshake and fixed for
   * the session's life (MC-01). Every request on the session is served against it — there is
   * no path by which a request reaches a different chain's runtime.
   */
  chainId: number;
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
  /**
   * The closed list of chains this wallet origin serves (D8). A handshake naming a chain
   * outside it — or naming none — is refused with `handshake:nack` before any request is
   * served (MC-03, MC-11). The list is disclosed only in that refusal and in the ack (MC-13).
   */
  servedChainIds: number[];
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
 * The handshake also negotiates the session's chain: the dApp's declaration is a request,
 * never an instruction — only the configured served list admits a chain (D2).
 */
export class TransportHost {
  private readonly options: TransportHostOptions;
  private readonly hostWindow: Window;
  private pinnedOrigin: string | null = null;
  private pinnedSource: MessageEventSource | null = null;
  private sdkVersion = 'unknown';
  private sessionChainId: number | null = null;
  private started = false;
  private readonly onMessage = (event: MessageEvent) => void this.handleMessage(event);

  constructor(options: TransportHostOptions) {
    this.options = options;
    this.hostWindow = options.hostWindow ?? window;
  }

  get dappOrigin(): string | null {
    return this.pinnedOrigin;
  }

  /** The chain granted for the current session, or null before a successful handshake. */
  get chainId(): number | null {
    return this.sessionChainId;
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

  /**
   * Refuses a handshake with a machine-readable reason (MC-04). Sent directly to the
   * requesting window — the session is NOT established, so nothing is pinned and no rpc
   * message will ever be processed for it.
   */
  private nack(event: MessageEvent, id: string, reason: HandshakeNackReason, message: string, withChains = true): void {
    if (!event.source) return;
    (event.source as Window).postMessage(
      {
        giano: PROTOCOL_VERSION,
        id,
        type: 'handshake:nack',
        payload: {
          reason,
          message,
          ...(withChains ? { supportedChainIds: this.options.servedChainIds } : {}),
        },
      } satisfies TransportMessage,
      { targetOrigin: event.origin },
    );
  }

  private async handleMessage(event: MessageEvent): Promise<void> {
    const message = parseTransportMessage(event.data);
    if (!message) return;

    if (message.type === 'handshake') {
      // origin pinning — unchanged, still first, still fail-closed
      if (this.pinnedOrigin) {
        if (event.origin !== this.pinnedOrigin || event.source !== this.pinnedSource) return;
      } else {
        if (!event.source || !this.isAllowedOrigin(event.origin)) {
          // Refused with a reason instead of silence: a misconfigured allow-list used to be
          // indistinguishable from a severed opener (both surfaced as HANDSHAKE_TIMEOUT).
          // The served-chains list is deliberately NOT disclosed to a disallowed origin.
          console.warn(
            `[giano] handshake refused: origin ${event.origin} is not in allowedDappOrigins (${JSON.stringify(this.options.allowedOrigins ?? [])})`,
          );
          this.nack(event, message.id, 'origin-not-allowed', 'this wallet does not accept connections from your origin', false);
          return;
        }
        this.pinnedOrigin = event.origin;
        this.pinnedSource = event.source;
      }

      // Chain negotiation (MC-03, MC-11): the dApp names a chain; only the configured list
      // admits one. A refusal here precedes everything — no consent screen, no passkey
      // ceremony, no request is ever served on an unnegotiated session (MC-85).
      const requested = message.payload.chainId;
      if (requested === undefined) {
        this.nack(event, message.id, 'chain-required', 'the connection must name the chain it will transact on — there is no default chain');
        return;
      }
      if (!this.options.servedChainIds.includes(requested)) {
        this.nack(
          event,
          message.id,
          'unsupported-chain',
          `this wallet does not serve chain ${requested} — it serves: ${this.options.servedChainIds.join(', ')}`,
        );
        return;
      }

      this.sessionChainId = requested;
      this.sdkVersion = message.payload.sdkVersion;
      this.post({
        giano: PROTOCOL_VERSION,
        id: message.id,
        type: 'handshake:ack',
        payload: {
          walletVersion: this.options.walletVersion ?? '0.0.0',
          capabilities: this.options.capabilities ?? [],
          chainId: requested,
          supportedChainIds: this.options.servedChainIds,
        },
      });
      this.options.onConnected?.({ dappOrigin: this.pinnedOrigin!, sdkVersion: this.sdkVersion, chainId: requested });
      return;
    }

    // everything else requires the pinned channel
    if (!this.pinnedOrigin || event.origin !== this.pinnedOrigin || event.source !== this.pinnedSource) return;

    if (message.type === 'rpc') {
      // A session exists only once the chain is negotiated; anything earlier is refused.
      if (this.sessionChainId === null) {
        this.post({
          giano: PROTOCOL_VERSION,
          id: message.id,
          type: 'rpc:response',
          payload: { error: { code: RPC_ERRORS.DISCONNECTED, message: 'no session — the handshake was not completed' } },
        });
        return;
      }
      try {
        const result = await this.options.onRequest(message.payload.method, message.payload.params, {
          dappOrigin: this.pinnedOrigin,
          sdkVersion: this.sdkVersion,
          chainId: this.sessionChainId,
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
