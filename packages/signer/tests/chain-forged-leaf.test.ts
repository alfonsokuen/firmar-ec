/**
 * chain-forged-leaf.test.ts — end-to-end regressions for the 2026-09-23 chain
 * validation defect (panel trío Opus + Fable + Kimi + Codex).
 *
 * pkijs 3.x's CertificateChainValidationEngine builds the path from the LAST
 * cert of `certs[]` (after a dedup that drops the LATER copy of a duplicate).
 * The verifier passed `[signerCert, ...intermediates]`, so pkijs validated
 * "whatever intermediate came last" and the signer's own issuance signature was
 * never checked. Two observable failures, both exercised here on real signed
 * PDFs:
 *
 *  1. False VALID — a leaf self-issued with the issuer DN of a real accredited
 *     subordinate CA (public data) verified as `valid` under the real root.
 *  2. False INVALID — in a multi-signature PDF the sibling signer's leaf ended
 *     up last in the pool; pkijs could not build ITS path and the genuine
 *     signer got `untrusted_root` (real case: UANATACA CA2 2016 + CA2 2021).
 *
 * Plus the signing-time trust issue: without an RFC 3161 timestamp the chain
 * was validated at the signer-declared `signingTime`, so an expired cert with
 * a backdated signing time verified as fully `valid`.
 */
import { webcrypto } from 'node:crypto';
import type { TrustIntermediate, TrustRoot } from '@firma-ec/tsl-ec';
import forge from 'node-forge';
import { PDFDocument, StandardFonts } from 'pdf-lib';
import * as pkijs from 'pkijs';
import { beforeAll, describe, expect, it } from 'vitest';

import { verifyAllSignatures } from '../../verifier/src/index.js';
import { addIncrementalSignature } from '../src/incrementalUpdate.js';
import { parsePfx } from '../src/p12.js';
import { signPdfPades } from '../src/pades.js';

beforeAll(() => {
  pkijs.setEngine(
    'node-webcrypto',
    new pkijs.CryptoEngine({ name: 'node-webcrypto', crypto: webcrypto as unknown as Crypto }),
  );
  if (!(globalThis as { crypto?: Crypto }).crypto) {
    (globalThis as unknown as { crypto: Crypto }).crypto = webcrypto as unknown as Crypto;
  }
});

const PIN = 'test1234';
const YEAR = 365 * 24 * 60 * 60 * 1000;
const NO_LTV = { timestamp: false, ltv: { longTerm: false, longTermArchive: false } } as const;

interface Gen {
  der: Uint8Array;
  keys: forge.pki.rsa.KeyPair;
  cert: forge.pki.Certificate;
}

function makeCert(opts: {
  cn: string;
  notBefore: Date;
  notAfter: Date;
  isCa: boolean;
  serial: string;
  issuer?: Gen;
  /** Forgery: copy `issuer`'s subject DN but sign with the leaf's OWN key. */
  forgeIssuerDnOnly?: boolean;
}): Gen {
  const keys = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = opts.serial;
  cert.validity.notBefore = opts.notBefore;
  cert.validity.notAfter = opts.notAfter;
  const attrs = [
    { name: 'commonName', value: opts.cn },
    { name: 'countryName', value: 'EC' },
  ];
  cert.setSubject(attrs);
  cert.setIssuer(opts.issuer ? opts.issuer.cert.subject.attributes : attrs);
  cert.setExtensions([
    { name: 'basicConstraints', cA: opts.isCa },
    opts.isCa
      ? { name: 'keyUsage', keyCertSign: true, cRLSign: true }
      : { name: 'keyUsage', digitalSignature: true, nonRepudiation: true },
  ] as forge.pki.CertificateExtension[]);
  const signingKey =
    opts.issuer && !opts.forgeIssuerDnOnly ? opts.issuer.keys.privateKey : keys.privateKey;
  cert.sign(signingKey, forge.md.sha256.create());
  const der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
  return { der: Uint8Array.from(der, (c) => c.charCodeAt(0)), keys, cert };
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const buf = await webcrypto.subtle.digest(
    'SHA-256',
    bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
  );
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
}

async function asRoot(slug: string, gen: Gen): Promise<TrustRoot> {
  return {
    slug,
    commonName: gen.cert.subject.getField('CN')?.value ?? slug,
    orgName: `${slug} Org`,
    country: 'EC',
    pemContent: forge.pki.certificateToPem(gen.cert),
    fingerprintSha256: await sha256Hex(gen.der),
    validFrom: gen.cert.validity.notBefore.toISOString(),
    validUntil: gen.cert.validity.notAfter.toISOString(),
    isPlaceholder: false,
  };
}

async function asIntermediate(
  slug: string,
  rootSlug: string,
  gen: Gen,
): Promise<TrustIntermediate> {
  return {
    slug,
    commonName: gen.cert.subject.getField('CN')?.value ?? slug,
    rootSlug,
    orgName: `${slug} Org`,
    pemContent: forge.pki.certificateToPem(gen.cert),
    fingerprintSha256: await sha256Hex(gen.der),
    validFrom: gen.cert.validity.notBefore.toISOString(),
    validUntil: gen.cert.validity.notAfter.toISOString(),
  } as TrustIntermediate;
}

/** .p12 with the leaf plus `chain` (pass [] for a leaf-only .p12). */
function p12(leaf: Gen, chain: Gen[] = []): Uint8Array {
  const asn = forge.pkcs12.toPkcs12Asn1(
    leaf.keys.privateKey,
    [leaf.cert, ...chain.map((g) => g.cert)],
    PIN,
    { algorithm: 'aes256', useMac: true, count: 2048 },
  );
  const der = forge.asn1.toDer(asn).getBytes();
  return Uint8Array.from(der, (c) => c.charCodeAt(0));
}

async function minimalPdf(): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  const page = doc.addPage([400, 200]);
  const font = await doc.embedFont(StandardFonts.Helvetica);
  page.drawText('chain forged-leaf test', { x: 50, y: 100, size: 14, font });
  return doc.save({ useObjectStreams: false });
}

async function sign(
  pdf: Uint8Array,
  leaf: Gen,
  chain: Gen[],
  extra: Record<string, unknown> = {},
): Promise<Uint8Array> {
  const pfx = await parsePfx(p12(leaf, chain), PIN);
  return (
    await signPdfPades(pdf, pfx as Parameters<typeof signPdfPades>[1], {
      ...NO_LTV,
      intermediateBundle: [],
      aiaFallback: null,
      ...extra,
    })
  ).signedPdf;
}

/** root → two parallel subordinate CAs (the real UANATACA CA2 2016 / CA2 2021 shape). */
function buildPki() {
  const now = Date.now();
  const root = makeCert({
    cn: 'Synth Root',
    notBefore: new Date(now - 5 * YEAR),
    notAfter: new Date(now + 15 * YEAR),
    isCa: true,
    serial: '01',
  });
  const interA = makeCert({
    cn: 'Synth CA2 2016',
    notBefore: new Date(now - 4 * YEAR),
    notAfter: new Date(now + 5 * YEAR),
    isCa: true,
    serial: '02',
    issuer: root,
  });
  const interB = makeCert({
    cn: 'Synth CA2 2021',
    notBefore: new Date(now - 3 * YEAR),
    notAfter: new Date(now + 8 * YEAR),
    isCa: true,
    serial: '03',
    issuer: root,
  });
  return { root, interA, interB };
}

function leafUnder(issuer: Gen, cn: string, serial: string, forged = false): Gen {
  return makeCert({
    cn,
    notBefore: new Date(Date.now() - YEAR),
    notAfter: new Date(Date.now() + YEAR),
    isCa: false,
    serial,
    issuer,
    forgeIssuerDnOnly: forged,
  });
}

describe('chain validation checks the SIGNER, not the last pooled cert', () => {
  it('forged leaf (issuer DN copied, own key) + real intermediate embedded → invalid', async () => {
    const { root, interB } = buildPki();
    const forged = leafUnder(interB, 'ATACANTE FALSO', '66', true);
    const signed = await sign(await minimalPdf(), forged, [interB]);
    const r = await verifyAllSignatures(signed, {
      trustRoots: [await asRoot('synth-root', root)],
      trustIntermediates: [],
      fetchOcsp: false,
    });
    const s = r.signatures[0]!;
    expect(s.status, 'a forged leaf must never verify under a real accredited root').toBe(
      'invalid',
    );
    expect(s.signer?.matchedRootSlug).toBeUndefined();
  });

  it('forged leaf, leaf-only CMS, bundle supplies the real intermediate → invalid', async () => {
    const { root, interA } = buildPki();
    const forged = leafUnder(interA, 'ATACANTE FALSO', '67', true);
    const signed = await sign(await minimalPdf(), forged, []);
    const r = await verifyAllSignatures(signed, {
      trustRoots: [await asRoot('synth-root', root)],
      trustIntermediates: [await asIntermediate('synth-ca2-2016', 'synth-root', interA)],
      fetchOcsp: false,
    });
    expect(r.signatures[0]!.status).toBe('invalid');
    expect(r.signatures[0]!.signer?.matchedRootSlug).toBeUndefined();
  });

  it('genuine leaf still verifies (control for the two forgeries above)', async () => {
    const { root, interB } = buildPki();
    const leaf = leafUnder(interB, 'FIRMANTE GENUINO', '68');
    const signed = await sign(await minimalPdf(), leaf, [interB]);
    const r = await verifyAllSignatures(signed, {
      trustRoots: [await asRoot('synth-root', root)],
      trustIntermediates: [],
      fetchOcsp: false,
    });
    expect(r.signatures[0]!.status).toBe('valid');
    expect(r.signatures[0]!.signer?.matchedRootSlug).toBe('synth-root');
  });

  it('multi-signature: leaf-only CA-A signer + CA-B signer with embedded intermediate → both valid', async () => {
    const { root, interA, interB } = buildPki();
    const leafA = leafUnder(interA, 'JOSE SINTETICO', '70');
    const leafB = leafUnder(interB, 'ALFONSO SINTETICO', '71');
    const once = await sign(await minimalPdf(), leafA, []);
    const pfxB = await parsePfx(p12(leafB, [interB]), PIN);
    const twice = await addIncrementalSignature(
      once,
      pfxB as Parameters<typeof addIncrementalSignature>[1],
      { ...NO_LTV, intermediateBundle: [], aiaFallback: null },
    );
    const r = await verifyAllSignatures(twice, {
      trustRoots: [await asRoot('synth-root', root)],
      trustIntermediates: [await asIntermediate('synth-ca2-2016', 'synth-root', interA)],
      fetchOcsp: false,
    });
    expect(r.signatureCount).toBe(2);
    for (const s of r.signatures) {
      expect(s.status, `${s.signer?.cert.subject.cn}: ${JSON.stringify(s.warnings)}`).not.toBe(
        'invalid',
      );
      expect(s.signer?.matchedRootSlug).toBe('synth-root');
    }
  });
});

describe('chain validity time is not taken on the signer’s word', () => {
  function expiredPki() {
    const { root, interA } = buildPki();
    const expired = makeCert({
      cn: 'CADUCADO',
      notBefore: new Date(Date.now() - 3 * YEAR),
      notAfter: new Date(Date.now() - 1 * YEAR),
      isCa: false,
      serial: '80',
      issuer: interA,
    });
    return { root, interA, expired };
  }

  it('expired cert + backdated signingTime, no timestamp → not valid, flagged', async () => {
    const { root, interA, expired } = expiredPki();
    const backdated = new Date(Date.now() - 2 * YEAR); // inside the cert's validity
    const signed = await sign(await minimalPdf(), expired, [interA], { signingTime: backdated });
    const r = await verifyAllSignatures(signed, {
      trustRoots: [await asRoot('synth-root', root)],
      trustIntermediates: [],
      fetchOcsp: false,
    });
    const s = r.signatures[0]!;
    expect(s.status, 'a signer-declared date alone cannot make an expired cert valid').not.toBe(
      'valid',
    );
    expect(s.warnings.some((w) => w.code === 'signing_time_unproven')).toBe(true);
  });

  it('expired cert signed with its real (current) date → invalid', async () => {
    const { root, interA, expired } = expiredPki();
    const signed = await sign(await minimalPdf(), expired, [interA], { signingTime: new Date() });
    const r = await verifyAllSignatures(signed, {
      trustRoots: [await asRoot('synth-root', root)],
      trustIntermediates: [],
      fetchOcsp: false,
    });
    expect(r.signatures[0]!.status).toBe('invalid');
    expect(r.signatures[0]!.warnings.map((w) => w.code)).toContain('signer_cert_not_valid');
  });
});
