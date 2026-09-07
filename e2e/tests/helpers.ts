import type { CDPSession, Page } from '@playwright/test';

export const WALLET_URL = process.env.WALLET_URL ?? 'http://wallet.localhost:8081';

/** A virtual-authenticator resident credential, as emitted by CDP `WebAuthn.credentialAdded`. */
export type VirtualCredential = Record<string, unknown>;

/**
 * Attaches a CDP virtual authenticator (resident-key P-256, user-verified) to the
 * given page — used on each POPUP page, where all WebAuthn happens.
 */
export async function addVirtualAuthenticator(page: Page): Promise<{ cdp: CDPSession; authenticatorId: string }> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return { cdp, authenticatorId };
}

/**
 * The wallet popup is ephemeral: it closes after each connect/sign/transaction, so every
 * later action opens a fresh popup with a fresh virtual authenticator. CDP authenticators
 * are per-page, so the resident passkey minted during connect must be re-seeded into each
 * new popup's authenticator (a real OS authenticator is shared across popups, so this only
 * papers over the virtual-authenticator limitation). We capture the credential from the
 * `credentialAdded` event the moment it is created — before the popup can close.
 */
export function trackResidentCredentials(cdp: CDPSession): VirtualCredential[] {
  const credentials: VirtualCredential[] = [];
  cdp.on('WebAuthn.credentialAdded' as never, ((event: { credential: VirtualCredential }) => {
    credentials.push(event.credential);
  }) as never);
  return credentials;
}

/** Injects previously-captured resident credentials into a popup's virtual authenticator. */
export async function seedCredentials(cdp: CDPSession, authenticatorId: string, credentials: VirtualCredential[]): Promise<void> {
  for (const credential of credentials) {
    await cdp.send('WebAuthn.addCredential' as never, { authenticatorId, credential } as never);
  }
}

/** Clicks a dApp button that opens the wallet popup and resolves the popup page. */
export async function openWalletPopup(dappPage: Page, trigger: string): Promise<Page> {
  const [popup] = await Promise.all([dappPage.waitForEvent('popup'), dappPage.click(trigger)]);
  await popup.waitForLoadState('domcontentloaded');
  return popup;
}

export async function expectOutContains(dappPage: Page, text: string, timeout = 90_000): Promise<void> {
  await dappPage.locator('[data-testid=out]').filter({ hasText: text }).waitFor({ timeout });
}
