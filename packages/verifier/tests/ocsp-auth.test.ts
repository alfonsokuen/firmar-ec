import { webcrypto } from 'node:crypto';
import * as asn1js from 'asn1js';
import forge from 'node-forge';
import * as pkijs from 'pkijs';
import { afterEach, beforeAll, describe, expect, test, vi } from 'vitest';
import { checkOcsp } from '../src/ocsp';

/**
 * ocsp-auth.test.ts — live OCSP answers are authenticated before use
 * (2026-09-23 panel, Codex finding 3).
 *
 * checkOcsp used to read `responses[0]` of whatever came back, with no check
 * of the responder's signature nor of the CertID. Once the chain fix handed
 * OCSP the real issuer, that answer started to decide verdicts, so a response
 * about another certificate, or with a broken signature, must not read `good`.
 */

beforeAll(() => {
  pkijs.setEngine(
    'node-webcrypto',
    new pkijs.CryptoEngine({ name: 'node-webcrypto', crypto: webcrypto as unknown as Crypto }),
  );
});
afterEach(() => vi.unstubAllGlobals());

const YEAR = 365 * 24 * 60 * 60 * 1000;

interface Gen {
  pkijsCert: pkijs.Certificate;
  privateKey: CryptoKey;
}

async function makeCert(
  cn: string,
  serial: string,
  issuer?: Gen & { forge: forge.pki.Certificate; forgeKey: forge.pki.rsa.PrivateKey },
) {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = serial;
  cert.validity.notBefore = new Date(Date.now() - YEAR);
  cert.validity.notAfter = new Date(Date.now() + YEAR);
  const attrs = [{ name: 'commonName', value: cn }];
  cert.setSubject(attrs);
  cert.setIssuer(issuer ? issuer.forge.subject.attributes : attrs);
  cert.setExtensions([{ name: 'basicConstraints', cA: !issuer }]);
  cert.sign(issuer ? issuer.forgeKey : keys.privateKey, forge.md.sha256.create());
  const der = Uint8Array.from(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes(), (c) =>
    c.charCodeAt(0),
  );
  const pkcs8 = Uint8Array.from(
    forge.asn1
      .toDer(forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(keys.privateKey)))
      .getBytes(),
    (c) => c.charCodeAt(0),
  );
  const privateKey = await webcrypto.subtle.importKey(
    'pkcs8',
    pkcs8,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return {
    pkijsCert: new pkijs.Certificate({ schema: asn1js.fromBER(der.buffer).result }),
    privateKey: privateKey as unknown as CryptoKey,
    forge: cert,
    forgeKey: keys.privateKey,
  };
}

/** A BasicOCSPResponse saying `good` for `about`, signed by `signer`, wrapped in an OCSPResponse. */
async function ocspGood(
  about: pkijs.Certificate,
  issuer: pkijs.Certificate,
  signer: Gen,
): Promise<Uint8Array> {
  const certID = new pkijs.CertID();
  await certID.createForCertificate(about, { hashAlgorithm: 'SHA-1', issuerCertificate: issuer });
  const single = new pkijs.SingleResponse({
    certID,
    certStatus: new asn1js.Primitive({ idBlock: { tagClass: 3, tagNumber: 0 }, lenBlockLength: 1 }),
    thisUpdate: new Date(Date.now() - 60_000),
  });
  const basic = new pkijs.BasicOCSPResponse();
  basic.tbsResponseData.responderID = issuer.subject;
  basic.tbsResponseData.producedAt = new Date();
  basic.tbsResponseData.responses.push(single);
  await basic.sign(signer.privateKey, 'SHA-256');
  const resp = new pkijs.OCSPResponse();
  resp.responseStatus.valueBlock.valueDec = 0;
  resp.responseBytes = new pkijs.ResponseBytes({
    responseType: '1.3.6.1.5.5.7.48.1.1',
    response: new asn1js.OctetString({ valueHex: basic.toSchema().toBER(false) }),
  });
  return new Uint8Array(resp.toSchema().toBER(false));
}

function serveOcsp(bytes: Uint8Array): void {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response(bytes, { status: 200 })),
  );
}

// One PKI for the file — forge RSA keygen is slow.
const ca = await makeCert('OCSP Test CA', '01');
const signer = await makeCert('SIGNER', '10', ca);
const other = await makeCert('SOMEONE ELSE', '11', ca);
const rogue = await makeCert('ROGUE RESPONDER', '99');

describe('checkOcsp authenticates the live response', () => {
  test('genuine issuer-signed good response for this cert → good (control)', async () => {
    serveOcsp(await ocspGood(signer.pkijsCert, ca.pkijsCert, ca));
    const r = await checkOcsp({
      signerCert: signer.pkijsCert,
      issuerCert: ca.pkijsCert,
      acSlug: 'x',
    });
    expect(r.status).toBe('good');
  });

  test('properly signed response about ANOTHER cert → not good', async () => {
    serveOcsp(await ocspGood(other.pkijsCert, ca.pkijsCert, ca));
    const r = await checkOcsp({
      signerCert: signer.pkijsCert,
      issuerCert: ca.pkijsCert,
      acSlug: 'x',
    });
    expect(r.status).not.toBe('good');
  });

  test('response signed by a key that is not the issuer nor a delegated responder → not good', async () => {
    serveOcsp(await ocspGood(signer.pkijsCert, ca.pkijsCert, rogue));
    const r = await checkOcsp({
      signerCert: signer.pkijsCert,
      issuerCert: ca.pkijsCert,
      acSlug: 'x',
    });
    expect(r.status).not.toBe('good');
  });
});
