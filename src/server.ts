import crypto from 'node:crypto';
import http from 'node:http';
import base64url from '@cfworker/base64url';
import cors from '@koa/cors';
import Router from '@koa/router';
import koa from 'koa';
import json from 'koa-better-json';
import { koaBody as body } from 'koa-body';
import { WebAuthnController } from 'oslo/webauthn';
import AuthService from './AuthService';
import * as helpers from './helpers';
import { base64URLToBuffer, byteStringToBuffer } from './helpers';

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

// unique identifier for your website
const rpID = 'localhost';
// human-readable identifier for your website
const rpName = 'WebAuthn PoC';
// URL at which registrations and authentications occur
const origins = ['http://localhost', 'http://localhost:3000', 'https://cryopdp.ngrok.dev'];

const usernameToChallenge = { 'bruce.wayne': 'hello' };

router.post('/api/register/start', async (ctx) => {
  // user chosen username
  const username = ctx.request.body.username;
  // challenge
  const challenge = 'hello'; // crypto.randomBytes(20).toString('hex');
  usernameToChallenge[username] = challenge;
  // previous user authenticators
  const userAuthenticators = [];

  const isMobile = ctx.headers['user-agent']?.match(/Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i) ? true : false;

  const options = {
    challenge,
    rp: {
      id: rpID,
      name: rpName,
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
      id: authenticator.credentialID,
      type: 'public-key',
      transports: authenticator.transports,
    })),
    authenticatorSelection: {
      userVerification: 'required',
      residentKey: 'required',
      // if user is on mobile then don't ask to save the passkey on another roaming device or the user will need another smartphone to register!
      // authenticatorAttachment: isMobile ? 'platform' : 'cross-platform',
      authenticatorAttachment: 'platform',
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
  if (!origins.includes(clientData.origin)) throw new Error("Failed to verify 'clientData.origin");

  await AuthService.saveUser(username, { username, id, publicKey, coseAlg, transports });
  ctx.body = true;
});

router.post('/api/login/start', async (ctx) => {
  const username = ctx.request.body.username;
  const userAuthenticator = await AuthService.getUser(username);
  const userAuthenticators = [userAuthenticator];

  const options = {
    rpID,
    challenge: usernameToChallenge[username],
    timeout: 60_000,
    // todo: add allowCredentials to narrow authenticator to registered one (ref: https://www.w3.org/TR/webauthn/#sctn-usecase-authentication)
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
  const { username, response: assertionResponse } = ctx.request.body;

  const user = await AuthService.getUser(username);
  const publicKey = user.publicKey;
  const expectedChallenge = usernameToChallenge[username];

  const wac = new WebAuthnController(origins[1]);

  ctx.body = await wac.validateAssertionResponse(
    'ES256',
    helpers.base64URLToBuffer(publicKey),
    {
      clientDataJSON: base64URLToBuffer(assertionResponse.clientDataJSON),
      authenticatorData: base64URLToBuffer(assertionResponse.authenticatorData),
      signature: base64URLToBuffer(assertionResponse.signature),
    },
    base64URLToBuffer(expectedChallenge),
  );

  return;

  const clientData = JSON.parse(helpers.bufferToByteString(helpers.base64URLToBuffer(assertionResponse.clientDataJSON)));

  if (clientData.type !== 'webauthn.get') throw new Error("Failed to verify 'clientData.type'");
  if (clientData.challenge !== base64url.encode(expectedChallenge)) throw new Error("Failed to verify 'clientData.challenge'");
  if (!origins.includes(clientData.origin)) throw new Error("Failed to verify 'clientData.origin");

  const authenticatorData = helpers.base64URLToBuffer(assertionResponse.authenticatorData);
  if (authenticatorData.byteLength < 37) throw new Error("Malformed 'authData'");
  const rpIdHash = authenticatorData.slice(0, 32);
  const rpIdData = new TextEncoder().encode(rpID);
  const expectedRpIdHash = new Uint8Array(await crypto.subtle.digest('SHA-256', rpIdData));
  if (!helpers.areBytewiseEqual(rpIdHash, expectedRpIdHash)) throw new Error("Failed to verify 'rpId' hash");

  const flagsBits = authenticatorData[32].toString(2);
  if (flagsBits.charAt(flagsBits.length - 1) !== '1') throw new Error('Failed to verify user present flag');

  const signature = helpers.convertDERSignatureToECDSASignature(assertionResponse.signature);
  const clientDataHash = new Uint8Array(await crypto.subtle.digest('SHA-256', helpers.byteStringToBuffer(assertionResponse.clientDataJSON)));
  const data = helpers.concatBuffers(authenticatorData, clientDataHash);

  const verifiedSignature = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    await crypto.subtle.importKey(
      'spki',
      helpers.base64URLToBuffer(publicKey),
      {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
      true,
      ['verify'],
    ),
    signature,
    data,
  );

  if (!verifiedSignature) throw new Error('Signature verification failed');
  ctx.body = true;
});

app.use(router.routes());
app.use(router.allowedMethods());
app.use(router.routes());

export const server = http.createServer(app.callback());
server.listen(process.env.PORT, () => console.info(`Listening on port ${String(process.env.PORT)}`));
