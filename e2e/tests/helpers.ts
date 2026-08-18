import type { CDPSession, Page } from '@playwright/test';

/**
 * Tenant descriptors for the two-tenant e2e topology. UI labels differ per tenant on
 * purpose: asserting them proves which wallet UI actually ran the flow (tenant A serves
 * Giano's stock wallet-web; tenant B serves the BYO fixture in e2e/wallet-byo/).
 */
export type Tenant = {
  slug: 'stock' | 'byo';
  walletUrl: string;
  dappUrl: string;
  adminKey: string;
  ui: { connect: string; approveTx: string; rejectTx: string; sign: string; txHeading: string };
};

export const TENANTS: Record<'stock' | 'byo', Tenant> = {
  stock: {
    slug: 'stock',
    walletUrl: process.env.WALLET_URL ?? 'http://wallet.localhost:8081',
    dappUrl: process.env.DAPP_URL ?? 'http://app.localhost:4400',
    adminKey: 'e2e-admin-key-stock',
    ui: { connect: 'Continue with passkey', approveTx: 'Approve', rejectTx: 'Reject', sign: 'Sign', txHeading: 'Review transaction' },
  },
  byo: {
    slug: 'byo',
    walletUrl: process.env.WALLET_BYO_URL ?? 'http://wallet-byo.localhost:8082',
    dappUrl: process.env.DAPP_BYO_URL ?? 'http://app-byo.localhost:4401',
    adminKey: 'e2e-admin-key-byo00',
    ui: { connect: 'Unlock with passkey', approveTx: 'Confirm', rejectTx: 'Decline', sign: 'Sign it', txHeading: 'Confirm transaction' },
  },
};

export const WALLET_URL = TENANTS.stock.walletUrl;

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

/** Reads the resident credentials currently stored on a virtual authenticator. */
export async function getCredentials(cdp: CDPSession, authenticatorId: string): Promise<VirtualCredential[]> {
  const result = (await cdp.send('WebAuthn.getCredentials' as never, { authenticatorId } as never)) as { credentials: VirtualCredential[] };
  return result.credentials;
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

/** Extracts the connected wallet address from the dApp's output log. */
export async function readConnectedAddress(dappPage: Page): Promise<string> {
  const out = await dappPage.locator('[data-testid=out]').textContent();
  const match = out?.match(/accounts: \["(0x[0-9a-fA-F]{40})"/);
  if (!match) throw new Error(`no connected address in dApp output:\n${out}`);
  return match[1];
}

/**
 * Connects a fresh wallet on the given tenant's dApp and returns the resident
 * credential(s) plus the connected address. NOTE: two dApps share the hardcoded popup
 * window name 'giano-wallet' — keep tenants in separate browser contexts.
 */
export async function connectWallet(page: Page, tenant: Tenant): Promise<{ credentials: VirtualCredential[]; address: string }> {
  await page.goto(tenant.dappUrl);
  const popup = await openWalletPopup(page, '#connect');
  const { cdp } = await addVirtualAuthenticator(popup);
  const credentials = trackResidentCredentials(cdp);
  await popup.getByRole('button', { name: tenant.ui.connect }).click();
  await expectOutContains(page, 'accounts: ["0x');
  return { credentials, address: await readConnectedAddress(page) };
}

/** Opens a fresh popup for a signing/transaction action, seeding the connect credential. */
export async function openActionPopup(page: Page, trigger: string, credentials: VirtualCredential[]): Promise<Page> {
  const popup = await openWalletPopup(page, trigger);
  const { cdp, authenticatorId } = await addVirtualAuthenticator(popup);
  await seedCredentials(cdp, authenticatorId, credentials);
  return popup;
}
