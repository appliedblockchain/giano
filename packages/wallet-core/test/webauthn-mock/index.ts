/**
 * WebAuthn / passkey mock — a real-crypto, in-memory platform authenticator plus
 * the glue to expose it as `window.navigator.credentials`, so any code that calls
 * `navigator.credentials.create/get` (ox, viem, the Giano provider) drives a real
 * P-256 keypair instead of hardware.
 *
 * Usage:
 *   const mock = installWebAuthnMock();
 *   // ...exercise code that uses navigator.credentials...
 *   mock.uninstall();
 */
import { MockAuthenticator, type MockAuthenticatorOptions } from './authenticator';

export { MockAuthenticator } from './authenticator';
export { toBase64Url } from './authenticator';
export type { MockAuthenticatorOptions } from './authenticator';

export type InstalledWebAuthnMock = {
  authenticator: MockAuthenticator;
  uninstall: () => void;
};

/**
 * Installs the mock as the global `navigator.credentials` (and `window.navigator`,
 * which `ox` reads by default). Returns the authenticator and an uninstall handle
 * that restores the previous globals.
 */
export function installWebAuthnMock(options: MockAuthenticatorOptions = {}): InstalledWebAuthnMock {
  const authenticator = new MockAuthenticator(options);
  const credentials = {
    create: (o: CredentialCreationOptions) => authenticator.create(o),
    get: (o: CredentialRequestOptions) => authenticator.get(o),
  };
  const navigatorLike = { credentials } as unknown as Navigator;
  // ox derives the default rp from `window.location.hostname` and `window.document.title`.
  const location = { hostname: new URL(authenticator.origin).hostname, origin: authenticator.origin };
  const documentLike = { title: 'Giano' } as unknown as Document;
  const windowLike = { navigator: navigatorLike, location, document: documentLike } as unknown as Window;

  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
  const previousWindow = Object.getOwnPropertyDescriptor(globalThis, 'window');
  const previousDocument = Object.getOwnPropertyDescriptor(globalThis, 'document');

  Object.defineProperty(globalThis, 'navigator', { value: navigatorLike, configurable: true, writable: true });
  Object.defineProperty(globalThis, 'window', { value: windowLike, configurable: true, writable: true });
  Object.defineProperty(globalThis, 'document', { value: documentLike, configurable: true, writable: true });

  const uninstall = () => {
    if (previousNavigator) Object.defineProperty(globalThis, 'navigator', previousNavigator);
    else delete (globalThis as Record<string, unknown>).navigator;
    if (previousWindow) Object.defineProperty(globalThis, 'window', previousWindow);
    else delete (globalThis as Record<string, unknown>).window;
    if (previousDocument) Object.defineProperty(globalThis, 'document', previousDocument);
    else delete (globalThis as Record<string, unknown>).document;
  };

  return { authenticator, uninstall };
}
