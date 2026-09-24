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
  opts: { ca?: boolean; ocspSigning?: boolean; notBefore?: Date; notAfter?: Date } = {},
) {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = serial;
  cert.validity.notBefore = opts.notBefore ?? new Date(Date.now() - YEAR);
  cert.validity.notAfter = opts.notAfter ?? new Date(Date.now() + YEAR);
  const attrs = [{ name: 'commonName', value: cn }];
  cert.setSubject(attrs);
  cert.setIssuer(issuer ? issuer.forge.subject.attributes : attrs);
  cert.setExtensions([
    { name: 'basicConstraints', cA: opts.ca ?? !issuer },
    ...(opts.ocspSigning ? [{ name: 'extKeyUsage', '1.3.6.1.5.5.7.3.9': true }] : []), // id-kp-OCSPSigning
  ]);
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
  nextUpdate?: Date;
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
  delegated: { responder?: pkijs.Certificate; certs?: pkijs.Certificate[]; producedAt?: Date } = {},
): Promise<Uint8Array> {
  const basic = new pkijs.BasicOCSPResponse();
  basic.tbsResponseData.responderID = (delegated.responder ?? responderIssuer).subject;
  basic.tbsResponseData.producedAt = delegated.producedAt ?? new Date();
  for (const e of entries) basic.tbsResponseData.responses.push(await singleResponse(e));
  if (delegated.certs) basic.certs = delegated.certs;
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
    ...(opts.nextUpdate ? { nextUpdate: opts.nextUpdate } : {}),
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

describe('delegated OCSP responders (RFC 6960 §4.2.2.2)', () => {
  // Opus + Fable (2026-09-23): pkijs's BasicOCSPResponse.verify builds a
  // chain from [responder, ...attached CAs] and validates the LAST one, not
  // the responder, so an impostor responder passed with any real CA attached.
  const ask = () =>
    checkOcsp({ signerCert: signer.pkijsCert, issuerCert: ca.pkijsCert, acSlug: 'x' });

  test('legit delegated responder issued by the CA → good', async () => {
    const responder = await makeCert('OCSP RESPONDER', '50', ca, { ca: false, ocspSigning: true });
    serveOcsp(
      await ocspMulti(
        [{ about: signer.pkijsCert, issuer: ca.pkijsCert }],
        ca.pkijsCert,
        responder,
        {
          responder: responder.pkijsCert,
          certs: [responder.pkijsCert],
        },
      ),
    );
    expect((await ask()).status).toBe('good');
  });

  test('legit delegated responder that also attaches the CA → good (no false warning)', async () => {
    const responder = await makeCert('OCSP RESPONDER 2', '51', ca, {
      ca: false,
      ocspSigning: true,
    });
    serveOcsp(
      await ocspMulti(
        [{ about: signer.pkijsCert, issuer: ca.pkijsCert }],
        ca.pkijsCert,
        responder,
        {
          responder: responder.pkijsCert,
          certs: [responder.pkijsCert, ca.pkijsCert],
        },
      ),
    );
    expect((await ask()).status).toBe('good');
  });

  test('self-signed impostor responder with a real CA-issued cert attached → not good', async () => {
    const impostor = await makeCert('IMPOSTOR', '52', undefined, { ca: false, ocspSigning: true });
    const realSubCa = await makeCert('REAL SUB CA', '53', ca, { ca: true });
    serveOcsp(
      await ocspMulti([{ about: signer.pkijsCert, issuer: ca.pkijsCert }], ca.pkijsCert, impostor, {
        responder: impostor.pkijsCert,
        certs: [impostor.pkijsCert, realSubCa.pkijsCert],
      }),
    );
    const r = await ask();
    expect(r.status).toBe('unknown');
    expect(r.reason).toBe('ocsp_signature_not_verified');
  });

  test('responder issued by the CA but without id-kp-OCSPSigning → not good', async () => {
    const noEku = await makeCert('NO EKU', '54', ca, { ca: false });
    serveOcsp(
      await ocspMulti([{ about: signer.pkijsCert, issuer: ca.pkijsCert }], ca.pkijsCert, noEku, {
        responder: noEku.pkijsCert,
        certs: [noEku.pkijsCert],
      }),
    );
    expect((await ask()).status).toBe('unknown');
  });

  test('responder not yet valid / expired at producedAt → not good', async () => {
    const expired = await makeCert('EXPIRED RESPONDER', '55', ca, {
      ca: false,
      ocspSigning: true,
      notBefore: new Date(Date.now() - 3 * YEAR),
      notAfter: new Date(Date.now() - 2 * YEAR),
    });
    serveOcsp(
      await ocspMulti([{ about: signer.pkijsCert, issuer: ca.pkijsCert }], ca.pkijsCert, expired, {
        responder: expired.pkijsCert,
        certs: [expired.pkijsCert],
      }),
    );
    expect((await ask()).status).toBe('unknown');
  });

  test('embedded historical response: responder valid at producedAt, expired now → still authenticated', async () => {
    const producedAt = new Date(Date.now() - 2 * YEAR);
    const oldResponder = await makeCert('OLD RESPONDER', '56', ca, {
      ca: false,
      ocspSigning: true,
      notBefore: new Date(Date.now() - 3 * YEAR),
      notAfter: new Date(Date.now() - YEAR),
    });
    const revokedAt = new Date(Date.now() - 2 * YEAR - 1000);
    const der = await ocspMulti(
      [{ about: signer.pkijsCert, issuer: ca.pkijsCert, revokedAt, thisUpdate: producedAt }],
      ca.pkijsCert,
      oldResponder,
      { responder: oldResponder.pkijsCert, certs: [oldResponder.pkijsCert], producedAt },
    );
    const ltv = await verifyLtv(
      [signer.pkijsCert, ca.pkijsCert],
      { certs: [], ocsps: [der], crls: [], vri: {} },
      new Uint8Array([1]),
      new Uint8Array(0),
    );
    expect(ltv.signerRevocation?.revokedAt?.toISOString()).toBe(revokedAt.toISOString());
  });
});

const DAY = 24 * 60 * 60 * 1000;
const ltvOf = (ocsps: Uint8Array[], crls: Uint8Array[] = [], proofTime = new Date()) =>
  verifyLtv(
    [signer.pkijsCert, ca.pkijsCert],
    { certs: [], ocsps, crls, vri: {} },
    new Uint8Array([1]),
    new Uint8Array(0),
    { proofTime },
  );

describe('embedded evidence must cover the proven signing time (all four reviewers, 2026-09-24)', () => {
  test('an old `good` (before the proof time, already expired) is not evidence', async () => {
    const old = await ocspResponse(signer.pkijsCert, ca.pkijsCert, ca, {
      thisUpdate: new Date(Date.now() - 3 * YEAR),
      nextUpdate: new Date(Date.now() - 3 * YEAR + 7 * DAY),
    });
    const ltv = await ltvOf([old]);
    expect(ltv.signerEvidence).toBeUndefined();
    expect(ltv.retrospectiveValid).toBe(false);
  });

  test('a `good` issued after the proof time is evidence (control)', async () => {
    const fresh = await ocspResponse(signer.pkijsCert, ca.pkijsCert, ca, {
      thisUpdate: new Date(Date.now() - DAY),
    });
    const ltv = await ltvOf([fresh], [], new Date(Date.now() - 2 * DAY));
    expect(ltv.signerEvidence).toBe(true);
    expect(ltv.retrospectiveValid).toBe(true);
  });

  test('a CRL skipped for size, with nothing else about the signer, leaves the check incomplete', async () => {
    const ltv = await ltvOf([], [new Uint8Array(100_001)]);
    expect(ltv.revocationIncomplete).toBe(true);
  });
});

async function buildCrl(opts: {
  entries?: { serial: pkijs.Certificate; reason?: number; at: Date }[];
  onlyCaCerts?: boolean;
  /** issuingDistributionPoint with only a distributionPoint name (still a full CRL). */
  plainIdp?: boolean;
  delta?: boolean;
  /** ExpiredCertsOnCRL (2.5.29.60): expired certs stay listed since this date. */
  expiredCertsOnCrl?: Date;
  thisUpdate?: Date;
  issuer?: Gen & { pkijsCert: pkijs.Certificate };
}): Promise<Uint8Array> {
  const signerCa = opts.issuer ?? ca;
  const crl = new pkijs.CertificateRevocationList();
  crl.version = 1;
  crl.signature.algorithmId = '1.2.840.113549.1.1.11';
  crl.issuer = signerCa.pkijsCert.subject;
  crl.thisUpdate = new pkijs.Time({
    type: 0,
    value: opts.thisUpdate ?? new Date(Date.now() - 60_000),
  });
  crl.nextUpdate = new pkijs.Time({ type: 0, value: new Date(Date.now() + 7 * DAY) });
  if (opts.entries?.length) {
    crl.revokedCertificates = opts.entries.map(
      (e) =>
        new pkijs.RevokedCertificate({
          userCertificate: e.serial.serialNumber,
          revocationDate: new pkijs.Time({ type: 0, value: e.at }),
          ...(e.reason !== undefined
            ? {
                crlEntryExtensions: new pkijs.Extensions({
                  extensions: [
                    new pkijs.Extension({
                      extnID: '2.5.29.21',
                      extnValue: new asn1js.Enumerated({ value: e.reason }).toBER(false),
                    }),
                  ],
                }),
              }
            : {}),
        }),
    );
  }
  const exts: pkijs.Extension[] = [];
  if (opts.onlyCaCerts || opts.plainIdp) {
    // IssuingDistributionPoint: [2] onlyContainsCACerts, or [0] a distributionPoint name.
    const dpName = new asn1js.Constructed({
      idBlock: { tagClass: 3, tagNumber: 0 },
      value: [
        new asn1js.Constructed({
          idBlock: { tagClass: 3, tagNumber: 0 },
          value: [
            new asn1js.Primitive({
              idBlock: { tagClass: 3, tagNumber: 6 },
              valueHex: new TextEncoder().encode('http://crl.test/full.crl').buffer,
            }),
          ],
        }),
      ],
    });
    const onlyCa = new asn1js.Primitive({
      idBlock: { tagClass: 3, tagNumber: 2 },
      valueHex: new Uint8Array([0xff]).buffer,
    });
    const idp = new asn1js.Sequence({ value: [opts.onlyCaCerts ? onlyCa : dpName] });
    exts.push(
      new pkijs.Extension({ extnID: '2.5.29.28', critical: true, extnValue: idp.toBER(false) }),
    );
  }
  if (opts.delta) {
    exts.push(
      new pkijs.Extension({
        extnID: '2.5.29.27',
        critical: true,
        extnValue: new asn1js.Integer({ value: 1 }).toBER(false),
      }),
    );
  }
  if (opts.expiredCertsOnCrl) {
    exts.push(
      new pkijs.Extension({
        extnID: '2.5.29.60',
        extnValue: new asn1js.GeneralizedTime({ valueDate: opts.expiredCertsOnCrl }).toBER(false),
      }),
    );
  }
  if (exts.length) crl.crlExtensions = new pkijs.Extensions({ extensions: exts });
  await crl.sign(signerCa.privateKey, 'SHA-256');
  return new Uint8Array(crl.toSchema(true).toBER(false));
}

describe('CRL scope and entry semantics', () => {
  test('a complete, current CRL that does not list the signer is evidence (control)', async () => {
    const ltv = await ltvOf([], [await buildCrl({})], new Date(Date.now() - DAY));
    expect(ltv.signerEvidence).toBe(true);
  });

  test('a CRL scoped to CA certs (issuingDistributionPoint) is not evidence about a user cert', async () => {
    const ltv = await ltvOf(
      [],
      [await buildCrl({ onlyCaCerts: true })],
      new Date(Date.now() - DAY),
    );
    expect(ltv.signerEvidence).toBeUndefined();
    expect(ltv.retrospectiveValid).toBe(false);
  });

  test('a removeFromCRL entry is a release, not a revocation', async () => {
    const crl = await buildCrl({
      entries: [{ serial: signer.pkijsCert, reason: 8, at: new Date(Date.now() - 10 * DAY) }],
    });
    const ltv = await ltvOf([], [crl], new Date(Date.now() - DAY));
    expect(ltv.signerRevocation).toBeUndefined();
  });

  test('a plain revocation entry is a revocation (control)', async () => {
    const at = new Date(Date.now() - 10 * DAY);
    const crl = await buildCrl({ entries: [{ serial: signer.pkijsCert, reason: 1, at }] });
    const ltv = await ltvOf([], [crl], new Date(Date.now() - DAY));
    expect(ltv.signerRevocation?.revokedAt?.getTime()).toBe(Math.floor(at.getTime() / 1000) * 1000);
  });
});

describe('a scoped or delta CRL still reports the revocations it lists (Opus, 2026-09-24)', () => {
  const at = new Date(Date.now() - 10 * DAY);
  test('signer listed in a CRL with a plain issuingDistributionPoint -> revoked', async () => {
    const crl = await buildCrl({
      plainIdp: true,
      entries: [{ serial: signer.pkijsCert, reason: 1, at }],
    });
    const ltv = await ltvOf([], [crl], new Date(Date.now() - DAY));
    expect(ltv.signerRevocation?.revokedAt).toBeDefined();
  });

  test('signer listed in a delta CRL -> revoked', async () => {
    const crl = await buildCrl({
      delta: true,
      entries: [{ serial: signer.pkijsCert, reason: 1, at }],
    });
    const ltv = await ltvOf([], [crl], new Date(Date.now() - DAY));
    expect(ltv.signerRevocation?.revokedAt).toBeDefined();
  });

  test('sub CA listed in the root ARL (onlyContainsCACerts) -> CA revocation', async () => {
    const root = await makeCert('ARL ROOT', '70');
    const sub = await makeCert('ARL SUB', '71', root, { ca: true });
    const leaf = await makeCert('ARL LEAF', '72', sub);
    const arl = await buildCrl({
      onlyCaCerts: true,
      issuer: root,
      entries: [{ serial: sub.pkijsCert, reason: 2, at }],
    });
    const ltv = await verifyLtv(
      [leaf.pkijsCert, sub.pkijsCert, root.pkijsCert],
      { certs: [], ocsps: [], crls: [arl], vri: {} },
      new Uint8Array([1]),
      new Uint8Array(0),
      { proofTime: new Date(Date.now() - DAY) },
    );
    expect(ltv.caRevocation?.revokedAt).toBeDefined();
  });
});

describe('favorable evidence issued after the certificate expired proves nothing (Codex + Opus)', () => {
  const expiredSigner = (cn: string, serial: string) =>
    makeCert(cn, serial, ca, {
      notBefore: new Date(Date.now() - 2 * YEAR),
      notAfter: new Date(Date.now() - 30 * DAY),
    });
  const ltvFor = (leaf: pkijs.Certificate, ocsps: Uint8Array[], crls: Uint8Array[]) =>
    verifyLtv(
      [leaf, ca.pkijsCert],
      { certs: [], ocsps, crls, vri: {} },
      new Uint8Array([1]),
      new Uint8Array(0),
      { proofTime: new Date(Date.now() - 60 * DAY) },
    );

  test('CRL from after expiry that no longer lists the cert -> not evidence', async () => {
    const expired = await expiredSigner('EXPIRED SIGNER', '80');
    const ltv = await ltvFor(expired.pkijsCert, [], [await buildCrl({})]);
    expect(ltv.signerEvidence).toBeUndefined();
    expect(ltv.retrospectiveValid).toBe(false);
  });

  test('same CRL declaring ExpiredCertsOnCRL from before expiry -> evidence (control)', async () => {
    const expired = await expiredSigner('EXPIRED SIGNER 2', '81');
    const crl = await buildCrl({ expiredCertsOnCrl: new Date(Date.now() - YEAR) });
    const ltv = await ltvFor(expired.pkijsCert, [], [crl]);
    expect(ltv.signerEvidence).toBe(true);
  });

  test('OCSP `good` produced after expiry -> not evidence', async () => {
    const expired = await expiredSigner('EXPIRED SIGNER 3', '82');
    const good = await ocspResponse(expired.pkijsCert, ca.pkijsCert, ca);
    const ltv = await ltvFor(expired.pkijsCert, [good], []);
    expect(ltv.signerEvidence).toBeUndefined();
  });
});

describe('skipped material leaves the check incomplete even with signer evidence (Codex)', () => {
  test('fresh signer OCSP good + a CRL skipped for size -> incomplete', async () => {
    const fresh = await ocspResponse(signer.pkijsCert, ca.pkijsCert, ca, {
      thisUpdate: new Date(Date.now() - DAY),
    });
    const ltv = await ltvOf([fresh], [new Uint8Array(100_001)], new Date(Date.now() - 2 * DAY));
    expect(ltv.revocationIncomplete).toBe(true);
  });
});
