import base64url from 'base64url';
import cbor from 'cbor';
import crypto from 'crypto';
import elliptic from 'elliptic';
import jsrsasign from 'jsrsasign';
import NodeRSA from 'node-rsa';

let COSEKEYS = {
  kty: 1,
  alg: 3,
  crv: -1,
  x: -2,
  y: -3,
  n: -1,
  e: -2,
};

let COSEKTY = {
  OKP: 1,
  EC2: 2,
  RSA: 3,
};

let COSERSASCHEME = {
  '-3': 'pss-sha256',
  '-39': 'pss-sha512',
  '-38': 'pss-sha384',
  '-65535': 'pkcs1-sha1',
  '-257': 'pkcs1-sha256',
  '-258': 'pkcs1-sha384',
  '-259': 'pkcs1-sha512',
};

var COSECRV = {
  1: 'p256',
  2: 'p384',
  3: 'p521',
};

var COSEALGHASH = {
  '-257': 'sha256',
  '-258': 'sha384',
  '-259': 'sha512',
  '-65535': 'sha1',
  '-39': 'sha512',
  '-38': 'sha384',
  '-37': 'sha256',
  '-260': 'sha256',
  '-261': 'sha512',
  '-7': 'sha256',
  '-36': 'sha512',
};

let hash = (alg, message) => {
  return crypto.createHash(alg).update(message).digest();
};

let base64ToPem = (b64cert) => {
  let pemcert = '';
  for (let i = 0; i < b64cert.length; i += 64) pemcert += b64cert.slice(i, i + 64) + '\n';

  return '-----BEGIN CERTIFICATE-----\n' + pemcert + '-----END CERTIFICATE-----';
};

var getCertificateInfo = (certificate) => {
  let subjectCert = new jsrsasign.X509();
  subjectCert.readCertPEM(certificate);

  let subjectString = subjectCert.getSubjectString();
  let subjectParts = subjectString.slice(1).split('/');

  let subject = {};
  for (let field of subjectParts) {
    let kv = field.split('=');
    subject[kv[0]] = kv[1];
  }

  let version = subjectCert.version;
  let basicConstraintsCA = !!subjectCert.getExtBasicConstraints().cA;

  return {
    subject,
    version,
    basicConstraintsCA,
  };
};

var parseAuthData = (buffer) => {
  let rpIdHash = buffer.slice(0, 32);
  buffer = buffer.slice(32);
  let flagsBuf = buffer.slice(0, 1);
  buffer = buffer.slice(1);
  let flagsInt = flagsBuf[0];
  let flags = {
    up: !!(flagsInt & 0x01),
    uv: !!(flagsInt & 0x04),
    at: !!(flagsInt & 0x40),
    ed: !!(flagsInt & 0x80),
    flagsInt,
  };

  let counterBuf = buffer.slice(0, 4);
  buffer = buffer.slice(4);
  let counter = counterBuf.readUInt32BE(0);

  let aaguid = undefined;
  let credID = undefined;
  let COSEPublicKey = undefined;

  if (flags.at) {
    aaguid = buffer.slice(0, 16);
    buffer = buffer.slice(16);
    let credIDLenBuf = buffer.slice(0, 2);
    buffer = buffer.slice(2);
    let credIDLen = credIDLenBuf.readUInt16BE(0);
    credID = buffer.slice(0, credIDLen);
    buffer = buffer.slice(credIDLen);
    COSEPublicKey = buffer;
  }

  return { rpIdHash, flagsBuf, flags, counter, counterBuf, aaguid, credID, COSEPublicKey };
};

let verifyPackedAttestation = (webAuthnResponse) => {
  let attestationBuffer = base64url.toBuffer(webAuthnResponse.response.attestationObject);
  let attestationStruct = cbor.decodeAllSync(attestationBuffer)[0];

  let authDataStruct = parseAuthData(attestationStruct.authData);

  let clientDataHashBuf = hash('sha256', base64url.toBuffer(webAuthnResponse.response.clientDataJSON));
  let signatureBaseBuffer = Buffer.concat([attestationStruct.authData, clientDataHashBuf]);

  let signatureBuffer = attestationStruct.attStmt.sig;
  let signatureIsValid = false;

  if (attestationStruct.attStmt.x5c) {
    /* ----- Verify FULL attestation ----- */
    let leafCert = base64ToPem(attestationStruct.attStmt.x5c[0].toString('base64'));
    let certInfo = getCertificateInfo(leafCert);

    if (certInfo.subject.OU !== 'Authenticator Attestation') throw new Error('Batch certificate OU MUST be set strictly to "Authenticator Attestation"!');

    if (!certInfo.subject.CN) throw new Error('Batch certificate CN MUST no be empty!');

    if (!certInfo.subject.O) throw new Error('Batch certificate CN MUST no be empty!');

    if (!certInfo.subject.C || certInfo.subject.C.length !== 2) throw new Error('Batch certificate C MUST be set to two character ISO 3166 code!');

    if (certInfo.basicConstraintsCA) throw new Error('Batch certificate basic constraints CA MUST be false!');

    if (certInfo.version !== 3) throw new Error('Batch certificate version MUST be 3(ASN1 2)!');

    signatureIsValid = crypto.createVerify('sha256').update(signatureBaseBuffer).verify(leafCert, signatureBuffer);
    /* ----- Verify FULL attestation ENDS ----- */
  } else if (attestationStruct.attStmt.ecdaaKeyId) {
    throw new Error('ECDAA IS NOT SUPPORTED YET!');
  } else {
    /* ----- Verify SURROGATE attestation ----- */
    let pubKeyCose = cbor.decodeAllSync(authDataStruct.COSEPublicKey)[0];
    let hashAlg = COSEALGHASH[pubKeyCose.get(COSEKEYS.alg)];
    if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.EC2) {
      let x = pubKeyCose.get(COSEKEYS.x);
      let y = pubKeyCose.get(COSEKEYS.y);

      let ansiKey = Buffer.concat([Buffer.from([0x04]), x, y]);

      let signatureBaseHash = hash(hashAlg, signatureBaseBuffer);

      let ec = new elliptic.ec(COSECRV[pubKeyCose.get(COSEKEYS.crv)]);
      let key = ec.keyFromPublic(ansiKey);

      signatureIsValid = key.verify(signatureBaseHash, signatureBuffer);
    } else if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.RSA) {
      let signingScheme = COSERSASCHEME[pubKeyCose.get(COSEKEYS.alg)];

      let key = new NodeRSA(undefined, { signingScheme });
      key.importKey(
        {
          n: pubKeyCose.get(COSEKEYS.n),
          e: 65537,
        },
        'components-public',
      );

      signatureIsValid = key.verify(signatureBaseBuffer, signatureBuffer);
    } else if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.OKP) {
      let x = pubKeyCose.get(COSEKEYS.x);
      let signatureBaseHash = hash(hashAlg, signatureBaseBuffer);

      let key = new elliptic.eddsa('ed25519');
      key.keyFromPublic(x);

      signatureIsValid = key.verify(signatureBaseHash, signatureBuffer);
    }
    /* ----- Verify SURROGATE attestation ENDS ----- */
  }

  if (!signatureIsValid) throw new Error('Failed to verify the signature!');

  return true;
};

let packedFullAttestationWebAuthnSample = {
  rawId: 'wsLryOAxXMU54s2fCSWPzWjXHOBKPploN-UHftj4_rpIu6BZxNXppm82f7Y6iX9FEOKKeS5-N2TALeyzLnJfAA',
  id: 'wsLryOAxXMU54s2fCSWPzWjXHOBKPploN-UHftj4_rpIu6BZxNXppm82f7Y6iX9FEOKKeS5-N2TALeyzLnJfAA',
  response: {
    clientDataJSON:
      'eyJjaGFsbGVuZ2UiOiJZTVdFVGYtUDc5aU1iLUJxZFRreVNOUmVPdmE3bksyaVZDOWZpQzhpR3ZZeXB1bkVPQ1pHWjYtWTVPVjFydk1pRGdBaldmRmk2VUMwV3lLR3NqQS1nQSIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG4ub3JnIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9',
    attestationObject:
      'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIhAIzOihC6Ba80o5JnoYOJJ_EtEVmWQcAvxVCnsCFnVRQZAiAfeIddLPsPl1FeSX8B5xZANcQKGNoO7pb0TZPnuJdebGN4NWOBWQKzMIICrzCCAZegAwIBAgIESFs9tjANBgkqhkiG9w0BAQsFADAhMR8wHQYDVQQDDBZZdWJpY28gRklETyBQcmV2aWV3IENBMB4XDTE4MDQxMjEwNTcxMFoXDTE4MTIzMTEwNTcxMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTIxMzkzOTEyNjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPss3TBDKMVySlDM5vYLrX0nqRtZ4eZvKXuJydQ9wrLHeIm08P-dAijLlG384BsZWJtngEqsl38oGJzNsyV0yiijbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS42MBMGCysGAQQBguUcAgEBBAQDAgQwMCEGCysGAQQBguUcAQEEBBIEEPigEfOMCk0VgAYXER-e3H0wDAYDVR0TAQH_BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAMvPkvVjXQiuvSZmGCB8NqTvGqhxyEfkoU-vz63PaaTsG3jEzjl0C7PZ26VxCvqWPJdM3P3e7Kp18sj4RjEHUmkya2PPipOwBd3p0qMQSQ8MeziCPLQ9uvGGb4YShcvaprMv4c21b4piza-znHneNCmmq-ZS4Y23o-vYv085_BEwyLPcmPjSZ5qWysCq7rVvZ7OWwcU1zu5RhSZyUKl8dzK9lAzs5OdRH2fzEewsW2OkB_Ow_jBvAxqwLXXTHuwMFaRfpmBoZuQlcofSrnwJ8KA-K-e0dKTz2zC8EbZrWYrSpbrHKyqxeBT6DkUd8H4tgAd5lOr_yqrtVmIaRfq07NmhhdXRoRGF0YVjElWkIjx7O4yMpVANdvRDXyuORMFonUbVZu4_Xy7IpvdRBAAAAAPigEfOMCk0VgAYXER-e3H0AQMLC68jgMVzFOeLNnwklj81o1xzgSj6ZaDflB37Y-P66SLugWcTV6aZvNn-2Ool_RRDiinkufjdkwC3ssy5yXwClAQIDJiABIVggAYD1TSpf120DSVxen8ki56kF1bmT4EXO-P0JnSk5mMwiWCB3TlMZBRqPY6llzDcfHd-oW0EHdaFNgBdlGGFobpHKlw',
  },
};

let packedSurrogateAttestationWebAuthnSample = {
  id: 'H6X2BnnjgOzu_Oj87vpRnwMJeJYVzwM3wtY1lhAfQ14',
  rawId: 'H6X2BnnjgOzu_Oj87vpRnwMJeJYVzwM3wtY1lhAfQ14',
  response: {
    attestationObject:
      'o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZzn__mNzaWdZAQCPypMLXWqtCZ1sc5QdjhH-pAzm8-adpfbemd5zsym2krscwV0EeOdTrdUOdy3hWj5HuK9dIX_OpNro2jKrHfUj_0Kp-u87iqJ3MPzs-D9zXOqkbWqcY94Zh52wrPwhGfJ8BiQp5T4Q97E042hYQRDKmtv7N-BT6dywiuFHxfm1sDbUZ_yyEIN3jgttJzjp_wvk_RJmb78bLPTlym83Y0Ws73K6FFeiqFNqLA_8a4V0I088hs_IEPlj8PWxW0wnIUhI9IcRf0GEmUwTBpbNDGpIFGOudnl_C3YuXuzK3R6pv2r7m9-9cIIeeYXD9BhSMBQ0A8oxBbVF7j-0xXDNrXHZaGF1dGhEYXRhWQFnSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAOKjVmSRjt0nqud40p1PeHgEAIB-l9gZ544Ds7vzo_O76UZ8DCXiWFc8DN8LWNZYQH0NepAEDAzn__iBZAQDAIqzybPPmgeL5OR6JKq9bWDiENJlN_LePQEnf1_sgOm4FJ9kBTbOTtWplfoMXg40A7meMppiRqP72A3tmILwZ5xKIyY7V8Y2t8X1ilYJol2nCKOpAEqGLTRJjF64GQxen0uFpi1tA6l6N-ZboPxjky4aidBdUP22YZuEPCO8-9ZTha8qwvTgZwMHhZ40TUPEJGGWOnHNlYmqnfFfk0P-UOZokI0rqtqqQGMwzV2RrH2kjKTZGfyskAQnrqf9PoJkye4KUjWkWnZzhkZbrDoLyTEX2oWvTTflnR5tAVMQch4UGgEHSZ00G5SFoc19nGx_UJcqezx5cLZsny-qQYDRjIUMBAAE',
    clientDataJSON:
      'eyJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjMwMDAiLCJjaGFsbGVuZ2UiOiJBWGtYV1hQUDNnTHg4T0xscGtKM2FSUmhGV250blNFTmdnbmpEcEJxbDFuZ0tvbDd4V3dldlVZdnJwQkRQM0xFdmRyMkVPU3RPRnBHR3huTXZYay1WdyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ',
  },
  type: 'public-key',
};

verifyPackedAttestation(packedFullAttestationWebAuthnSample);
verifyPackedAttestation(packedSurrogateAttestationWebAuthnSample);
