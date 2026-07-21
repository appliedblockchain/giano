import type { CDPSession, Page } from '@playwright/test';

export const WALLET_URL = process.env.WALLET_URL ?? 'http://wallet.localtest.me:8081';

/**
 * Attaches a CDP virtual authenticator (resident-key P-256, user-verified) to the
 * given page — used on the POPUP page, where all WebAuthn happens.
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

/** Clicks a dApp button that opens the wallet popup and resolves the popup page. */
export async function openWalletPopup(dappPage: Page, trigger: string): Promise<Page> {
  const [popup] = await Promise.all([dappPage.waitForEvent('popup'), dappPage.click(trigger)]);
  await popup.waitForLoadState('domcontentloaded');
  return popup;
}

export async function expectOutContains(dappPage: Page, text: string, timeout = 90_000): Promise<void> {
  await dappPage.locator('[data-testid=out]').filter({ hasText: text }).waitFor({ timeout });
}
