import http from 'node:http';
import base64url from '@cfworker/base64url';
import cors from '@koa/cors';
import Router from '@koa/router';
import { generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse } from '@simplewebauthn/server';
import koa from 'koa';
import json from 'koa-better-json';
import { koaBody as body } from 'koa-body';
import AuthService from './AuthService';

const app = new koa();
app.use(cors());
app.use(body());
app.use(json({ pretty: true, spaces: 2 }));

app.use(async (ctx, next) => {
  try {
    await next();
  } catch (error: any) {
    console.error(error);
    ctx.status = error.status;
    ctx.body = error.message;
  }
});

const router = new Router();

// Human-readable title for your website
const rpName = 'WebAuthn PoC';
// A unique identifier for your website
const rpID = ['localhost', 'cryopdp.ngrok.dev'];
// The URL at which registrations and authentications should occur
const origin = [`http://${rpID}:3000`, 'https://cryopdp.ngrok.dev'];

const challengeToUsername = {};

router.post('/api/register/start', async (ctx) => {
  // challenge
  const challenge = 'hello';
  // user's specified username
  const userID = 'xyz';
  const username = ctx.request.body.username;
  // previous user authenticators
  const userAuthenticators = [];

  challengeToUsername['hello'] = username;

  const isMobile = ctx.headers['user-agent']?.match(/Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i) ? true : false;

  const registrationOptions = await generateRegistrationOptions({
    rpName,
    rpID,
    challenge,
    userID: userID,
    userName: username,
    attestationType: 'none', // Don't prompt users for additional information about the authenticator (smoother UX)
    // Prevent users from re-registering existing authenticators
    excludeCredentials: userAuthenticators.map((authenticator) => ({
      id: authenticator.credentialID,
      type: 'public-key',
      transports: authenticator.transports,
    })),
    // See "Guiding use of authenticators via authenticatorSelection" below
    authenticatorSelection: {
      residentKey: 'required',
      userVerification: 'required',
      // if user is on mobile then don't ask to save the passkey on another roaming device or the user will need another smartphone smartphone to register!
      // authenticatorAttachment: isMobile ? 'platform' : 'cross-platform',
      authenticatorAttachment: 'platform',
    },
  });

  ctx.body = registrationOptions;
});

router.post('/api/register/complete', async (ctx) => {
  const username = ctx.request.body.username;

  const verification = await verifyRegistrationResponse({
    response: ctx.request.body,
    expectedChallenge: base64url.encode('hello'),
    expectedOrigin: origin,
  });

  const { verified, registrationInfo } = verification;
  console.log(verified, registrationInfo);
  ctx.body = verified;

  if (!verified) throw new Error('Registration failed because attestation could not be verified.');

  await AuthService.saveUser(username, registrationInfo);
  return true;
});

router.post('/api/login/start', async (ctx) => {
  const username = ctx.request.body.username;
  const userAuthenticator = await AuthService.getUser(username);
  const userAuthenticators = [userAuthenticator];

  const options = await generateAuthenticationOptions({
    rpID,
    challenge: 'world',
    // Require users to use a previously-registered authenticator
    allowCredentials: userAuthenticators.map((authenticator) => ({
      id: authenticator.credentialID,
      type: 'public-key',
      transports: authenticator.transports || undefined,
    })),
    userVerification: 'required',
  });

  ctx.body = options;
});

router.post('/api/login/complete', async (ctx) => {
  const username = ctx.request.body.username;
  const userAuthenticator = await AuthService.getUser(username);

  const verification = await verifyAuthenticationResponse({
    response: ctx.request.body,
    expectedChallenge: base64url.encode('world'),
    expectedOrigin: origin,
    expectedRPID: rpID,
    authenticator: userAuthenticator,
  });

  const { verified } = verification;
  if (!verified) throw new Error('Login failed because attestation could not be verified.');

  ctx.body = verified;
});

app.use(router.routes());
app.use(router.allowedMethods());
app.use(router.routes());

export const server = http.createServer(app.callback());
server.listen(process.env.PORT, () => console.info(`Listening on port ${String(process.env.PORT)}`));
