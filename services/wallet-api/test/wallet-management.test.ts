import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { pendingAdditions, walletManagementLog } from '../src/db/schema.js';
import { generateClaimCode, normaliseClaimCode } from '../src/routes/wallet-management.js';
import { ownerKeyOf, startTestStack, stopTestStack, TENANT_A, TENANT_B, type TestContext } from './setup.js';
import { createAuthenticator, makeAuthenticationResponse, makeRegistrationResponse, type TestAuthenticator } from './webauthn-fixtures.js';

/**
 * The wallet-management API: credential names (WM-07/WM-08), the pending-addition
 * lifecycle (WM-18…WM-23), wallet-scoped binding (WM-15/WM-16), wallet-scoped sessions
 * (WM-33), removal (WM-30/WM-31) and the audit trail (WM-50…WM-52).
 *
 * The mock chain's owner-set state (ctx.chainState) plays the account contract's part:
 * the endpoints must refuse to update the registry unless the chain confirms the change.
 */

let ctx: TestContext;

beforeAll(async () => {
  ctx = await startTestStack();
}, 120_000);

afterAll(async () => {
  if (ctx) await stopTestStack(ctx);
});

const ORIGIN = TENANT_A.walletOrigin;

type Session = { token: string };
type Registered = { walletAddress: string; credentialId: string; session: Session };

const getOptions = async (externalUserId: string, kind: string) => {
  const res = await ctx.app.inject({
    method: 'POST',
    url: '/v1/webauthn/options',
    headers: { origin: ORIGIN },
    payload: { externalUserId, kind },
  });
  expect(res.statusCode).toBe(200);
  return res.json() as { challenge: string; credentialIds: string[] };
};

const register = async (externalUserId: string, auth: TestAuthenticator, credentialName?: string): Promise<Registered> => {
  const options = await getOptions(externalUserId, 'registration');
  const res = await ctx.app.inject({
    method: 'POST',
    url: '/v1/webauthn/registration/verify',
    headers: { origin: ORIGIN },
    payload: {
      externalUserId,
      ...(credentialName ? { credentialName } : {}),
      response: makeRegistrationResponse(auth, { challenge: options.challenge, origin: ORIGIN, rpId: TENANT_A.rpId }),
    },
  });
  expect(res.statusCode).toBe(200);
  return res.json() as Registered;
};

const authenticate = async (auth: TestAuthenticator, externalUserId: string) => {
  const options = await getOptions(externalUserId, 'authentication');
  return ctx.app.inject({
    method: 'POST',
    url: '/v1/webauthn/authentication/verify',
    headers: { origin: ORIGIN },
    payload: { response: makeAuthenticationResponse(auth, { challenge: options.challenge, origin: ORIGIN, rpId: TENANT_A.rpId }) },
  });
};

const authed = (token: string) => ({ origin: ORIGIN, authorization: `Bearer ${token}` });

const listCredentials = async (token: string) => {
  const res = await ctx.app.inject({ method: 'GET', url: '/v1/me/credentials', headers: authed(token) });
  expect(res.statusCode).toBe(200);
  return (res.json() as { credentials: { credentialId: string; walletAddress: string; name: string | null; publicKeyX: string; publicKeyY: string; removedAt: string | null }[] }).credentials;
};

const openSlot = async (token: string) => {
  const res = await ctx.app.inject({ method: 'POST', url: '/v1/wallet/pending-additions', headers: authed(token) });
  expect(res.statusCode).toBe(200);
  return res.json() as { id: string; claimCode: string; expiresAt: string };
};

const claim = (claimCode: string) =>
  ctx.app.inject({ method: 'POST', url: '/v1/wallet/pending-additions/claim', headers: { origin: ORIGIN }, payload: { claimCode } });

const fill = async (claimCode: string, auth: TestAuthenticator) => {
  const claimed = await claim(claimCode);
  expect(claimed.statusCode).toBe(200);
  const { challenge } = claimed.json() as { challenge: string };
  return ctx.app.inject({
    method: 'POST',
    url: '/v1/wallet/pending-additions/claim/fill',
    headers: { origin: ORIGIN },
    payload: { claimCode, response: makeRegistrationResponse(auth, { challenge, origin: ORIGIN, rpId: TENANT_A.rpId }) },
  });
};

const keyHex = (auth: TestAuthenticator) => ({
  x: `0x${auth.publicKeyX.toString('hex')}`,
  y: `0x${auth.publicKeyY.toString('hex')}`,
});

describe('credential names (WM-07, WM-08)', () => {
  it('persists the credentialName given at registration instead of discarding it', async () => {
    const { session } = await register('names-user', createAuthenticator(), 'My laptop');
    const credentials = await listCredentials(session.token);
    expect(credentials).toHaveLength(1);
    expect(credentials[0].name).toBe('My laptop');
  });

  it('renames a credential and the name persists across sessions', async () => {
    const auth = createAuthenticator();
    const { session, credentialId } = await register('rename-user', auth);
    const renamed = await ctx.app.inject({
      method: 'PATCH',
      url: `/v1/me/credentials/${encodeURIComponent(credentialId)}`,
      headers: authed(session.token),
      payload: { name: 'The phone I still have' },
    });
    expect(renamed.statusCode).toBe(200);

    // a fresh session (a different device, later) sees the same name
    const second = await authenticate(auth, 'rename-user');
    expect(second.statusCode).toBe(200);
    const { session: freshSession } = second.json() as Registered;
    const credentials = await listCredentials(freshSession.token);
    expect(credentials[0].name).toBe('The phone I still have');
  });
});

describe('claim codes', () => {
  it('normalises confusable characters and separators', () => {
    expect(normaliseClaimCode('ab-3o Il9')).toBe('AB30119');
    expect(normaliseClaimCode(generateClaimCode())).toHaveLength(8);
  });
});

describe('pending-addition lifecycle (WM-18…WM-23)', () => {
  it('binds a deposited credential to the EXISTING wallet once the chain confirms (WM-12, WM-15)', async () => {
    const deviceA = createAuthenticator();
    const deviceB = createAuthenticator();
    const { walletAddress, session } = await register('handoff-user', deviceA, 'Device A');

    const slot = await openSlot(session.token);
    const filled = await fill(slot.claimCode, deviceB);
    expect(filled.statusCode).toBe(200);
    const { publicKey } = filled.json() as { publicKey: { x: string; y: string } };
    expect(publicKey).toEqual(keyHex(deviceB));

    // device A polls and sees the deposited key — what it derives the fingerprint from (WM-20)
    const polled = await ctx.app.inject({ method: 'GET', url: `/v1/wallet/pending-additions/${slot.id}`, headers: authed(session.token) });
    expect(polled.statusCode).toBe(200);
    expect((polled.json() as { status: string; publicKey: unknown }).status).toBe('filled');
    expect((polled.json() as { publicKey: { x: string } }).publicKey.x).toBe(publicKey.x);

    // before the chain carries the owner, binding is refused — the registry never claims
    // an owner the chain does not have
    const premature = await ctx.app.inject({
      method: 'POST',
      url: `/v1/wallet/pending-additions/${slot.id}/complete`,
      headers: authed(session.token),
      payload: { chainIds: [31337], name: 'Device B' },
    });
    expect(premature.statusCode).toBe(409);
    expect((premature.json() as { error: string }).error).toBe('not-an-owner-on-chain');

    // ...the chain now carries it (the userop confirmed)...
    ctx.chainState.contracts.add(walletAddress.toLowerCase());
    ctx.chainState.ownerKeys.add(ownerKeyOf(publicKey.x, publicKey.y));

    const completed = await ctx.app.inject({
      method: 'POST',
      url: `/v1/wallet/pending-additions/${slot.id}/complete`,
      headers: authed(session.token),
      payload: { chainIds: [31337], name: 'Device B' },
    });
    expect(completed.statusCode).toBe(200);

    // bound, never derived: the new credential's wallet is device A's wallet
    const credentials = await listCredentials(session.token);
    expect(credentials).toHaveLength(2);
    for (const credential of credentials) expect(credential.walletAddress).toBe(walletAddress);
    expect(credentials.map((credential) => credential.name).sort()).toEqual(['Device A', 'Device B']);

    // WM-33: the second credential opens a session scoped to the SAME wallet
    const signedIn = await authenticate(deviceB, 'handoff-user');
    expect(signedIn.statusCode).toBe(200);
    expect((signedIn.json() as Registered).walletAddress).toBe(walletAddress);
    const me = await ctx.app.inject({ method: 'GET', url: '/v1/me', headers: authed((signedIn.json() as Registered).session.token) });
    expect((me.json() as { walletAddress: string }).walletAddress).toBe(walletAddress);

    // consumed slots are single-use (WM-22)
    const again = await ctx.app.inject({
      method: 'POST',
      url: `/v1/wallet/pending-additions/${slot.id}/complete`,
      headers: authed(session.token),
      payload: { chainIds: [31337] },
    });
    expect(again.statusCode).toBe(409);
    expect((again.json() as { error: string }).error).toBe('pending-consumed');
  });

  it('refuses a bind from a session scoped to another wallet (WM-16)', async () => {
    const { session } = await register('victim-user', createAuthenticator());
    const attacker = await register('attacker-user', createAuthenticator());

    const slot = await openSlot(session.token);
    // indistinguishable from an unknown slot: no oracle about other users' pending additions
    const foreignPoll = await ctx.app.inject({
      method: 'GET',
      url: `/v1/wallet/pending-additions/${slot.id}`,
      headers: authed(attacker.session.token),
    });
    expect(foreignPoll.statusCode).toBe(404);
    const foreignComplete = await ctx.app.inject({
      method: 'POST',
      url: `/v1/wallet/pending-additions/${slot.id}/complete`,
      headers: authed(attacker.session.token),
      payload: { chainIds: [31337] },
    });
    expect(foreignComplete.statusCode).toBe(404);
    expect((await listCredentials(attacker.session.token)).length).toBe(1);
  });

  it('refuses an unknown, expired or declined slot with distinct actionable reasons (WM-22, WM-23, WM-52)', async () => {
    const { session, walletAddress } = await register('expiry-user', createAuthenticator());

    const unknown = await claim('ZZZZZZZZ');
    expect(unknown.statusCode).toBe(404);
    expect((unknown.json() as { error: string }).error).toBe('pending-unknown');

    // expired: backdate the deadline — the claim must say "expired", not "unknown" and
    // not a generic failure
    const expiring = await openSlot(session.token);
    await ctx.db.update(pendingAdditions).set({ expiresAt: sql`now() - interval '1 minute'` }).where(eq(pendingAdditions.id, expiring.id));
    const expired = await claim(expiring.claimCode);
    expect(expired.statusCode).toBe(410);
    expect((expired.json() as { error: string }).error).toBe('pending-expired');
    // WM-22: not resumable after expiry — completing is refused too
    const expiredComplete = await ctx.app.inject({
      method: 'POST',
      url: `/v1/wallet/pending-additions/${expiring.id}/complete`,
      headers: authed(session.token),
      payload: { chainIds: [31337] },
    });
    expect(expiredComplete.statusCode).toBe(410);

    // declined fingerprint (WM-52): the slot dies and the decline is counted durably
    const declining = await openSlot(session.token);
    const filled = await fill(declining.claimCode, createAuthenticator());
    expect(filled.statusCode).toBe(200);
    const declined = await ctx.app.inject({
      method: 'POST',
      url: `/v1/wallet/pending-additions/${declining.id}/decline`,
      headers: authed(session.token),
    });
    expect(declined.statusCode).toBe(200);
    const afterDecline = await ctx.app.inject({
      method: 'POST',
      url: `/v1/wallet/pending-additions/${declining.id}/complete`,
      headers: authed(session.token),
      payload: { chainIds: [31337] },
    });
    expect(afterDecline.statusCode).toBe(409);
    expect((afterDecline.json() as { error: string }).error).toBe('pending-declined');

    const declineRows = await ctx.db
      .select()
      .from(walletManagementLog)
      .where(eq(walletManagementLog.walletAddress, walletAddress));
    expect(declineRows.some((row) => row.action === 'pending-declined')).toBe(true);
    expect(declineRows.some((row) => row.action === 'pending-expired')).toBe(true);
    expect(declineRows.some((row) => row.action === 'pending-opened')).toBe(true);
  });

  it('routes the claim within the tenant only — a foreign tenant origin cannot claim the code', async () => {
    const { session } = await register('tenant-scope-user', createAuthenticator());
    const slot = await openSlot(session.token);
    const foreign = await ctx.app.inject({
      method: 'POST',
      url: '/v1/wallet/pending-additions/claim',
      headers: { origin: TENANT_B.walletOrigin },
      payload: { claimCode: slot.claimCode },
    });
    expect(foreign.statusCode).toBe(404);
  });

  it('caps concurrently open slots per user (WM-19 rate limiting)', async () => {
    const { session } = await register('cap-user', createAuthenticator());
    for (let i = 0; i < ctx.config.PENDING_ADDITION_MAX_OPEN_PER_USER; i++) {
      await openSlot(session.token);
    }
    const overflow = await ctx.app.inject({ method: 'POST', url: '/v1/wallet/pending-additions', headers: authed(session.token) });
    expect(overflow.statusCode).toBe(429);
  });

  it('leaves a filled slot inert: no owner, no session, and a second fill is refused', async () => {
    const deviceB = createAuthenticator();
    const { session } = await register('inert-user', createAuthenticator());
    const slot = await openSlot(session.token);
    expect((await fill(slot.claimCode, deviceB)).statusCode).toBe(200);

    // nothing was added to the registry by the deposit alone
    expect((await listCredentials(session.token)).length).toBe(1);
    // and the deposited credential cannot authenticate — it is not registered anywhere
    const signIn = await authenticate(deviceB, 'inert-user');
    expect(signIn.statusCode).toBe(400);

    // the code's routing job is done: a second claim (and so a second fill) is refused
    const reclaimed = await claim(slot.claimCode);
    expect(reclaimed.statusCode).toBe(409);
    expect((reclaimed.json() as { error: string }).error).toBe('pending-already-filled');
  });
});

describe('removal (WM-29…WM-31)', () => {
  /** Registers a two-credential wallet by running the full handoff. */
  const twoCredentialWallet = async (label: string) => {
    const deviceA = createAuthenticator();
    const deviceB = createAuthenticator();
    const registered = await register(label, deviceA, 'first');
    const slot = await openSlot(registered.session.token);
    const filled = await fill(slot.claimCode, deviceB);
    const { publicKey } = filled.json() as { publicKey: { x: string; y: string } };
    ctx.chainState.contracts.add(registered.walletAddress.toLowerCase());
    ctx.chainState.ownerKeys.add(ownerKeyOf(publicKey.x, publicKey.y));
    ctx.chainState.ownerKeys.add(ownerKeyOf(keyHex(deviceA).x, keyHex(deviceA).y));
    const completed = await ctx.app.inject({
      method: 'POST',
      url: `/v1/wallet/pending-additions/${slot.id}/complete`,
      headers: authed(registered.session.token),
      payload: { chainIds: [31337], name: 'second' },
    });
    expect(completed.statusCode).toBe(200);
    const credentialIdB = (completed.json() as { credentialId: string }).credentialId;
    return { deviceA, deviceB, registered, credentialIdB, publicKeyB: publicKey };
  };

  it('refuses to mark a credential removed while the chain still lists it (chain governs, WM-36)', async () => {
    const { registered, credentialIdB } = await twoCredentialWallet('removal-guard-user');
    const refused = await ctx.app.inject({
      method: 'POST',
      url: `/v1/me/credentials/${encodeURIComponent(credentialIdB)}/removed`,
      headers: authed(registered.session.token),
    });
    expect(refused.statusCode).toBe(409);
    expect((refused.json() as { error: string }).error).toBe('still-an-owner');
  });

  it('marks a removed owner, revokes its sessions, and refuses it at authentication with a WM-31 reason', async () => {
    const { deviceB, registered, credentialIdB, publicKeyB } = await twoCredentialWallet('removal-user');

    // the removed device holds a live session — it must not survive the removal
    const removedDeviceSignIn = await authenticate(deviceB, 'removal-user');
    expect(removedDeviceSignIn.statusCode).toBe(200);
    const removedDeviceToken = (removedDeviceSignIn.json() as Registered).session.token;

    // the chain no longer lists the key (removeOwnerAtIndex confirmed)
    ctx.chainState.ownerKeys.delete(ownerKeyOf(publicKeyB.x, publicKeyB.y));

    const removed = await ctx.app.inject({
      method: 'POST',
      url: `/v1/me/credentials/${encodeURIComponent(credentialIdB)}/removed`,
      headers: authed(registered.session.token),
    });
    expect(removed.statusCode).toBe(200);
    expect((removed.json() as { removedCurrentSession: boolean }).removedCurrentSession).toBe(false);

    // its sessions are gone now, not at natural expiry (WM-31)
    const staleSession = await ctx.app.inject({ method: 'GET', url: '/v1/me', headers: authed(removedDeviceToken) });
    expect(staleSession.statusCode).toBe(401);

    // authentication is refused with a reason that says WHY — not a generic failure
    const refusedSignIn = await authenticate(deviceB, 'removal-user');
    expect(refusedSignIn.statusCode).toBe(403);
    expect((refusedSignIn.json() as { error: string }).error).toBe('credential-removed');

    // the registry still SHOWS the credential, marked removed (WM-04) — not silently dropped
    const credentials = await listCredentials(registered.session.token);
    const removedRow = credentials.find((credential) => credential.credentialId === credentialIdB);
    expect(removedRow).toBeDefined();
    expect(removedRow!.removedAt).not.toBeNull();

    // options for sign-in no longer offer the removed credential
    const options = await getOptions('removal-user', 'authentication');
    expect(options.credentialIds).not.toContain(credentialIdB);
  });

  it('permits removing the credential the session is bound to, ending that session (WM-30)', async () => {
    const { deviceB, registered, credentialIdB, publicKeyB } = await twoCredentialWallet('self-removal-user');

    // device B signs in and removes ITSELF (decommissioning the device in hand)
    const signedIn = await authenticate(deviceB, 'self-removal-user');
    const tokenB = (signedIn.json() as Registered).session.token;
    ctx.chainState.ownerKeys.delete(ownerKeyOf(publicKeyB.x, publicKeyB.y));

    const removed = await ctx.app.inject({
      method: 'POST',
      url: `/v1/me/credentials/${encodeURIComponent(credentialIdB)}/removed`,
      headers: authed(tokenB),
    });
    expect(removed.statusCode).toBe(200);
    expect((removed.json() as { removedCurrentSession: boolean }).removedCurrentSession).toBe(true);

    // the calling session is revoked — signed-out state
    const afterwards = await ctx.app.inject({ method: 'GET', url: '/v1/me', headers: authed(tokenB) });
    expect(afterwards.statusCode).toBe(401);

    // the OTHER credential's session is untouched
    const survivor = await ctx.app.inject({ method: 'GET', url: '/v1/me', headers: authed(registered.session.token) });
    expect(survivor.statusCode).toBe(200);
  });
});

describe('audit (WM-50)', () => {
  it('records owner events for changes the registry has no row for (an EOA owner)', async () => {
    const { session, walletAddress } = await register('audit-user', createAuthenticator());
    const logged = await ctx.app.inject({
      method: 'POST',
      url: '/v1/wallet/owner-events',
      headers: authed(session.token),
      payload: {
        action: 'owner-added',
        ownerKind: 'address',
        owner: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
        chainIds: [31337],
      },
    });
    expect(logged.statusCode).toBe(200);
    const rows = await ctx.db.select().from(walletManagementLog).where(eq(walletManagementLog.walletAddress, walletAddress));
    expect(rows).toHaveLength(1);
    expect(rows[0].action).toBe('owner-added');
    expect((rows[0].detail as { ownerKind: string }).ownerKind).toBe('address');
  });
});
