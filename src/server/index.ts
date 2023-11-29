import crypto from 'node:crypto';
import http from 'node:http';
import base64url from '@cfworker/base64url';
import cors from '@koa/cors';
import Router from '@koa/router';
import koa from 'koa';
import json from 'koa-better-json';
import { koaBody as body } from 'koa-body';
import * as helpers from '../misc/helpers';
import verifyAssertion from '../misc/verifyAssertion';
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
    ctx.status = error.status ?? 500;
    ctx.body = error.message ?? 'Internal Server Error.';
  }
});

const router = new Router();

const usernameToChallenge = { 'bruce.wayne': 'hello' };

router.post('/api/register/start', async (ctx) => {
  const username = ctx.request.body.username;

  const user = await AuthService.getUser(username);
  if (user) throw new Error('Username already exists.');

  const challenge = crypto.randomBytes(20).toString('hex');
  usernameToChallenge[username] = challenge;
  const userAuthenticators = [];

  const isMobile = ctx.headers['user-agent']?.match(/Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i) ? true : false;

  const options = {
    challenge,
    rp: {
      id: process.env.RP_ID,
      name: process.env.RP_NAME,
    },
    user: {
      id: username,
      name: username,
      displayName: username,
    },
    pubKeyCredParams: [
      {
        alg: -7,
        type: 'public-key',
      },
      {
        alg: -257,
        type: 'public-key',
      },
    ],
    // prevent users from re-registering existing authenticators
    excludeCredentials: userAuthenticators.map((authenticator) => ({
      id: authenticator.id,
      type: 'public-key',
      transports: authenticator.transports,
    })),
    authenticatorSelection: {
      userVerification: 'required',
      residentKey: 'required',
      // if user is on mobile then don't ask to save the passkey on another roaming device or the user will need another smartphone to register!
      authenticatorAttachment: isMobile ? 'platform' : 'cross-platform',
      // authenticatorAttachment: 'platform',
    },
    attestation: 'none',
    timeout: 60_000,
    extensions: {
      credProps: true,
    },
  };

  ctx.body = options;
});

router.post('/api/register/complete', async (ctx) => {
  const { username, id, publicKey, coseAlg, transports, clientDataJSON, attestationObject } = ctx.request.body;

  const clientData = JSON.parse(helpers.bufferToByteString(helpers.base64URLToBuffer(clientDataJSON)));

  const expectedChallenge = usernameToChallenge[username];

  if (clientData.type !== 'webauthn.create') throw new Error("Failed to verify 'clientData.type'");
  if (clientData.challenge !== base64url.encode(expectedChallenge)) throw new Error("Failed to verify 'clientData.challenge'");
  if (!process.env.RP_ORIGINS.split(',').includes(clientData.origin)) throw new Error("Failed to verify 'clientData.origin");

  await AuthService.saveUser(username, { username, id, publicKey, coseAlg, transports });
  ctx.body = true;
});

router.post('/api/login/start', async (ctx) => {
  const username = ctx.request.body.username;
  const userAuthenticator = await AuthService.getUser(username);
  const userAuthenticators = [userAuthenticator];

  const options = {
    rpID: process.env.RP_ID,
    challenge: usernameToChallenge[username],
    timeout: 60_000,
    // narrow authenticators choice to registered one (ref: https://www.w3.org/TR/webauthn/#sctn-usecase-authentication)
    // todo: is this really used or enforced?
    allowCredentials: userAuthenticators.map((authenticator) => ({
      id: authenticator.id,
      type: 'public-key',
      transports: authenticator.transports || undefined,
    })),
    userVerification: 'required',
  };

  ctx.body = options;
});

router.post('/api/login/complete', async (ctx) => {
  const { username, id, rawId, response } = ctx.request.body;

  const assertion = { id, rawId, response };

  const user = await AuthService.getUser(username);
  const publicKey = user.public_key;
  const expectedChallenge = usernameToChallenge[username];

  const verifiedSignature = await verifyAssertion(assertion, expectedChallenge, process.env.RP_ID, process.env.RP_ORIGINS.split(','), publicKey);

  if (!verifiedSignature) throw new Error('Signature verification failed');
  ctx.body = true;
});

app.use(router.routes());
app.use(router.allowedMethods());
app.use(router.routes());

export const server = http.createServer(app.callback());
server.listen(process.env.PORT, () => console.info(`Listening on port ${String(process.env.PORT)}`));
