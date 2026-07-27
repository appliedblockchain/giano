/**
 * Deterministic two-window harness: implements exactly the Window surface the
 * transport uses (message listeners, postMessage with origin/source semantics,
 * opener/closed), so tests exercise the real protocol including origin pinning.
 */

type Listener = (event: { data: unknown; origin: string; source: unknown }) => void;

export class FakeWindow {
  listeners = new Set<Listener>();
  closed = false;
  opener: FakeWindow | null = null;
  origin: string;

  constructor(origin: string) {
    this.origin = origin;
  }

  addEventListener(_type: string, listener: Listener): void {
    this.listeners.add(listener);
  }

  removeEventListener(_type: string, listener: Listener): void {
    this.listeners.delete(listener);
  }

  /** Deliver a message INTO this window as if `from` posted it. */
  receive(data: unknown, from: FakeWindow): void {
    // structured-clone-ish: force plain JSON like the real channel would
    const cloned = JSON.parse(JSON.stringify(data));
    for (const listener of [...this.listeners]) {
      listener({ data: cloned, origin: from.origin, source: from });
    }
  }

  focus(): void {}
  close(): void {
    this.closed = true;
  }
}

/** Wires postMessage(data, targetOrigin) from each side to the other's listeners. */
export function createWindowPair(dappOrigin: string, walletOrigin: string) {
  const dappWindow = new FakeWindow(dappOrigin);
  const popupWindow = new FakeWindow(walletOrigin);
  popupWindow.opener = dappWindow;

  // the popup window object as seen from the dApp: posting to it delivers into the popup
  const popupHandle = {
    closed: false,
    location: { href: 'about:blank' },
    focus: () => popupWindow.focus(),
    close: () => {
      popupHandle.closed = true;
      popupWindow.close();
    },
    postMessage: (data: unknown, targetOrigin: string | { targetOrigin?: string }) => {
      const target = typeof targetOrigin === 'string' ? targetOrigin : (targetOrigin?.targetOrigin ?? '*');
      if (target !== '*' && target !== walletOrigin) return; // browser drops mismatched targetOrigin
      popupWindow.receive(data, dappWindowHandle as unknown as FakeWindow);
    },
  };

  // the dApp window object as seen from the popup (its opener)
  const dappWindowHandle = {
    postMessage: (data: unknown, targetOrigin: string | { targetOrigin?: string }) => {
      const target = typeof targetOrigin === 'string' ? targetOrigin : (targetOrigin?.targetOrigin ?? '*');
      if (target !== '*' && target !== dappOrigin) return;
      // the source the dApp sees is the popup handle it opened
      const cloned = JSON.parse(JSON.stringify(data));
      for (const listener of [...dappWindow.listeners]) {
        listener({ data: cloned, origin: walletOrigin, source: popupHandle });
      }
    },
  };

  // fix identity: messages the dApp posts into the popup must appear as source === dappWindowHandle
  popupHandle.postMessage = (data: unknown, targetOrigin: string | { targetOrigin?: string }) => {
    const target = typeof targetOrigin === 'string' ? targetOrigin : (targetOrigin?.targetOrigin ?? '*');
    if (target !== '*' && target !== walletOrigin) return;
    const cloned = JSON.parse(JSON.stringify(data));
    for (const listener of [...popupWindow.listeners]) {
      listener({ data: cloned, origin: dappOrigin, source: dappWindowHandle });
    }
  };

  const hostWindow = {
    opener: dappWindowHandle,
    addEventListener: popupWindow.addEventListener.bind(popupWindow),
    removeEventListener: popupWindow.removeEventListener.bind(popupWindow),
  };

  return { dappWindow, popupWindow, popupHandle, dappWindowHandle, hostWindow };
}

export const flush = () => new Promise((resolve) => setTimeout(resolve, 0));
