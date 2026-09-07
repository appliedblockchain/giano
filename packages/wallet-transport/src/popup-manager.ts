import { TransportError } from './errors';

export type PopupManagerOptions = {
  url: string;
  width?: number;
  height?: number;
  /** Overridable for tests. */
  parent?: Pick<Window, 'open' | 'screenX' | 'screenY' | 'innerWidth' | 'innerHeight'>;
};

const DEFAULT_WIDTH = 420;
const DEFAULT_HEIGHT = 640;

/**
 * Opens and tracks the wallet popup.
 *
 * Safari quirk: the window MUST be opened synchronously inside the user gesture or it
 * is blocked — so `open()` opens `about:blank` immediately and only then navigates to
 * the wallet URL. Callers must invoke `open()` directly from the gesture handler.
 */
export class PopupManager {
  private popup: Window | null = null;
  readonly url: string;
  private readonly width: number;
  private readonly height: number;
  private readonly parent: NonNullable<PopupManagerOptions['parent']>;

  constructor(options: PopupManagerOptions) {
    this.url = options.url;
    this.width = options.width ?? DEFAULT_WIDTH;
    this.height = options.height ?? DEFAULT_HEIGHT;
    this.parent = options.parent ?? window;
  }

  get current(): Window | null {
    return this.popup && !this.popup.closed ? this.popup : null;
  }

  open(): Window {
    const existing = this.current;
    if (existing) {
      existing.focus?.();
      return existing;
    }

    const left = this.parent.screenX + Math.max(0, (this.parent.innerWidth - this.width) / 2);
    const top = this.parent.screenY + Math.max(0, (this.parent.innerHeight - this.height) / 2);
    const features = `width=${this.width},height=${this.height},left=${left},top=${top},popup=1,resizable,scrollbars`;

    // open about:blank synchronously (user-activation), navigate after
    const popup = this.parent.open('about:blank', 'giano-wallet', features);
    if (!popup) {
      throw new TransportError('POPUP_BLOCKED', 'the browser blocked the wallet popup — call from a user gesture and check COOP headers');
    }
    try {
      popup.location.href = this.url;
    } catch {
      // cross-origin navigation restrictions: fall back to closing + reopening directly
      popup.close();
      const direct = this.parent.open(this.url, 'giano-wallet', features);
      if (!direct) {
        throw new TransportError('POPUP_BLOCKED', 'the browser blocked the wallet popup');
      }
      this.popup = direct;
      return direct;
    }
    this.popup = popup;
    return popup;
  }

  close(): void {
    this.popup?.close();
    this.popup = null;
  }
}
