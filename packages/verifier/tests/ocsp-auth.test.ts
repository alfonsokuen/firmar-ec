import { webcrypto } from 'node:crypto';
import * as asn1js from 'asn1js';
import forge from 'node-forge';
import * as pkijs from 'pkijs';
import { afterEach, beforeAll, describe, expect, test, vi } from 'vitest';
import { verifyLtv } from '../src/ltv';
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

interface OcspOpts {
  /** Revoked at this date (with CRLReason `affiliationChanged`); default `good`. */
  revokedAt?: Date;
  thisUpdate?: Date;
  /** Build the CertID's issuer hashes from this cert instead of the real issuer. */
  certIdIssuer?: pkijs.Certificate;
}

/** A BasicOCSPResponse about `about`, signed by `signer`, wrapped in an OCSPResponse. */
async function ocspResponse(
  about: pkijs.Certificate,
  issuer: pkijs.Certificate,
  signer: Gen,
  opts: OcspOpts = {},
): Promise<Uint8Array> {
  return ocspMulti([{ about, issuer, ...opts }], issuer, signer);
}

/** One response carrying several SingleResponses (RFC 6960 allows extra entries). */
async function ocspMulti(
  entries: (OcspOpts & { about: pkijs.Certificate; issuer: pkijs.Certificate })[],
  responderIssuer: pkijs.Certificate,
  signer: Gen,
): Promise<Uint8Array> {
  const basic = new pkijs.BasicOCSPResponse();
  basic.tbsResponseData.responderID = responderIssuer.subject;
  basic.tbsResponseData.producedAt = new Date();
  for (const e of entries) basic.tbsResponseData.responses.push(await singleResponse(e));
  await basic.sign(signer.privateKey, 'SHA-256');
  const resp = new pkijs.OCSPResponse();
  resp.responseStatus.valueBlock.valueDec = 0;
  resp.responseBytes = new pkijs.ResponseBytes({
    responseType: '1.3.6.1.5.5.7.48.1.1',
    response: new asn1js.OctetString({ valueHex: basic.toSchema().toBER(false) }),
  });
  return new Uint8Array(resp.toSchema().toBER(false));
}

async function singleResponse(
  opts: OcspOpts & { about: pkijs.Certificate; issuer: pkijs.Certificate },
): Promise<pkijs.SingleResponse> {
  const { about, issuer } = opts;
  const certID = new pkijs.CertID();
  await certID.createForCertificate(about, {
    hashAlgorithm: 'SHA-1',
    issuerCertificate: opts.certIdIssuer ?? issuer,
  });
  const certStatus = opts.revokedAt
    ? new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 1 },
        value: [
          new asn1js.GeneralizedTime({ valueDate: opts.revokedAt }),
          new asn1js.Constructed({
            idBlock: { tagClass: 3, tagNumber: 0 },
            value: [new asn1js.Enumerated({ value: 3 })],
          }),
        ],
      })
    : new asn1js.Primitive({ idBlock: { tagClass: 3, tagNumber: 0 }, lenBlockLength: 1 });
  return new pkijs.SingleResponse({
    certID,
    certStatus,
    thisUpdate: opts.thisUpdate ?? new Date(Date.now() - 60_000),
  });
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
    serveOcsp(await ocspResponse(signer.pkijsCert, ca.pkijsCert, ca));
    const r = await checkOcsp({
      signerCert: signer.pkijsCert,
      issuerCert: ca.pkijsCert,
      acSlug: 'x',
    });
    expect(r.status).toBe('good');
  });

  test('properly signed response about ANOTHER cert → not good', async () => {
    serveOcsp(await ocspResponse(other.pkijsCert, ca.pkijsCert, ca));
    const r = await checkOcsp({
      signerCert: signer.pkijsCert,
      issuerCert: ca.pkijsCert,
      acSlug: 'x',
    });
    expect(r.status).not.toBe('good');
  });

  test('response signed by a key that is not the issuer nor a delegated responder → not good', async () => {
    serveOcsp(await ocspResponse(signer.pkijsCert, ca.pkijsCert, rogue));
    const r = await checkOcsp({
      signerCert: signer.pkijsCert,
      issuerCert: ca.pkijsCert,
      acSlug: 'x',
    });
    expect(r.status).not.toBe('good');
  });
});

describe('checkOcsp reads what the responder actually said', () => {
  test('revoked response carries its real revocation date and reason', async () => {
    const revokedAt = new Date('2026-07-01T00:00:00Z');
    serveOcsp(await ocspResponse(signer.pkijsCert, ca.pkijsCert, ca, { revokedAt }));
    const r = await checkOcsp({
      signerCert: signer.pkijsCert,
      issuerCert: ca.pkijsCert,
      acSlug: 'x',
    });
    expect(r.status).toBe('revoked');
    expect(r.revokedAt).toBe(revokedAt.toISOString());
    expect(r.reason).toBe('affiliationChanged');
  });

  test('old response without nextUpdate is not taken as current', async () => {
    serveOcsp(
      await ocspResponse(signer.pkijsCert, ca.pkijsCert, ca, {
        thisUpdate: new Date('2021-01-01T00:00:00Z'),
      }),
    );
    const r = await checkOcsp({
      signerCert: signer.pkijsCert,
      issuerCert: ca.pkijsCert,
      acSlug: 'x',
    });
    expect(r.status).toBe('unknown');
    expect(r.reason).toBe('ocsp_response_not_current');
  });

  test('response whose CertID names another issuer (same serial) → not good', async () => {
    serveOcsp(
      await ocspResponse(signer.pkijsCert, ca.pkijsCert, ca, { certIdIssuer: rogue.pkijsCert }),
    );
    const r = await checkOcsp({
      signerCert: signer.pkijsCert,
      issuerCert: ca.pkijsCert,
      acSlug: 'x',
    });
    expect(r.status).toBe('unknown');
    expect(r.reason).toBe('ocsp_response_unusable');
  });

  test('same serial under a foreign issuer (revoked, fresher) and the real one (revoked) → the real entry', async () => {
    const revokedAt = new Date('2026-07-01T00:00:00Z');
    serveOcsp(
      await ocspMulti(
        [
          {
            about: signer.pkijsCert,
            issuer: ca.pkijsCert,
            certIdIssuer: rogue.pkijsCert,
            revokedAt: new Date('2026-08-15T00:00:00Z'),
            thisUpdate: new Date(Date.now() - 1_000),
          },
          {
            about: signer.pkijsCert,
            issuer: ca.pkijsCert,
            revokedAt,
            thisUpdate: new Date(Date.now() - 3_600_000),
          },
        ],
        ca.pkijsCert,
        ca,
      ),
    );
    const r = await checkOcsp({
      signerCert: signer.pkijsCert,
      issuerCert: ca.pkijsCert,
      acSlug: 'x',
    });
    expect(r.status).toBe('revoked');
    expect(r.revokedAt).toBe(revokedAt.toISOString());
  });
});

describe('embedded (DSS) OCSP evidence does not depend on its order', () => {
  const revokedAt = new Date('2026-07-01T00:00:00Z');
  for (const order of ['good-first', 'revoked-first'] as const) {
    test(`${order}: an authenticated revocation of the signer is always reported, with its date`, async () => {
      const good = await ocspResponse(signer.pkijsCert, ca.pkijsCert, ca);
      const revoked = await ocspResponse(signer.pkijsCert, ca.pkijsCert, ca, { revokedAt });
      const ocsps = order === 'good-first' ? [good, revoked] : [revoked, good];
      const ltv = await verifyLtv(
        [signer.pkijsCert, ca.pkijsCert],
        { certs: [], ocsps, crls: [], vri: {} },
        new Uint8Array([1]),
        new Uint8Array(0),
      );
      expect(ltv.signerRevocation?.revokedAt?.toISOString()).toBe(revokedAt.toISOString());
      expect(ltv.retrospectiveValid).toBe(false);
    });
  }
});

describe('the earliest authenticated revocation decides, whatever the DSS order', () => {
  const early = new Date('2026-03-01T00:00:00Z');
  const late = new Date('2026-08-01T00:00:00Z');
  for (const order of ['late-first', 'early-first'] as const) {
    test(`${order}: two signed revocations with different dates → the earlier one`, async () => {
      const a = await ocspResponse(signer.pkijsCert, ca.pkijsCert, ca, { revokedAt: late });
      const b = await ocspResponse(signer.pkijsCert, ca.pkijsCert, ca, { revokedAt: early });
      const ltv = await verifyLtv(
        [signer.pkijsCert, ca.pkijsCert],
        { certs: [], ocsps: order === 'late-first' ? [a, b] : [b, a], crls: [], vri: {} },
        new Uint8Array([1]),
        new Uint8Array(0),
      );
      expect(ltv.signerRevocation?.revokedAt?.toISOString()).toBe(early.toISOString());
    });
  }
});
