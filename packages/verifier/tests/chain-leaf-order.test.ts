import { digest, toHex } from '@firma-ec/crypto-core';
import type { TrustIntermediate, TrustRoot } from '@firma-ec/tsl-ec';
import { fromBER } from 'asn1js';
import forge from 'node-forge';
import { Certificate } from 'pkijs';
import { describe, expect, test } from 'vitest';
import { checkCertificate } from '../src/certCheck';
import { validatePath } from '../src/pathValidation';

/**
 * chain-leaf-order.test.ts — validatePath / checkCertificate must validate the
 * SIGNER's chain (2026-09-23 panel trío, CRITICAL).
 *
 * pkijs 3.x builds the path from the LAST cert of `certs[]`, after a dedup that
 * removes the LATER copy of a duplicate. validatePath used to pass
 * `[signerCert, ...intermediates]`, so pkijs validated the last intermediate
 * and the signer's issuance signature was never checked:
 *  - a leaf self-signed with a real subordinate CA's issuer DN came out
 *    `success: true` under the real root (false VALID);
 *  - a sibling signer's leaf left last in a multi-signature pool made pkijs
 *    fail on ITS path, rejecting a genuine signer (false INVALID).
 */

const YEAR = 365 * 24 * 60 * 60 * 1000;

interface Gen {
  der: Uint8Array;
  keys: forge.pki.rsa.KeyPair;
  cert: forge.pki.Certificate;
}

function makeCert(opts: {
  cn: string;
  isCa: boolean;
  serial: string;
  issuer?: Gen;
  forgeIssuerDnOnly?: boolean;
  keyUsage?: Record<string, boolean>;
}): Gen {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = opts.serial;
  cert.validity.notBefore = new Date(Date.now() - YEAR);
  cert.validity.notAfter = new Date(Date.now() + 5 * YEAR);
  const attrs: forge.pki.CertificateField[] = [{ name: 'commonName', value: opts.cn }];
  cert.setSubject(attrs);
  cert.setIssuer(opts.issuer ? opts.issuer.cert.subject.attributes : attrs);
  const ku =
    opts.keyUsage ??
    (opts.isCa
      ? { keyCertSign: true, cRLSign: true }
      : { digitalSignature: true, nonRepudiation: true });
  cert.setExtensions([
    { name: 'basicConstraints', cA: opts.isCa },
    { name: 'keyUsage', ...ku },
  ]);
  const signingKey =
    opts.issuer && !opts.forgeIssuerDnOnly ? opts.issuer.keys.privateKey : keys.privateKey;
  cert.sign(signingKey, forge.md.sha256.create());
  const der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
  return { der: Uint8Array.from(der, (c) => c.charCodeAt(0)), keys, cert };
}

function toPkijs(gen: Gen): Certificate {
  const buf = gen.der.buffer.slice(gen.der.byteOffset, gen.der.byteOffset + gen.der.byteLength);
  return new Certificate({ schema: fromBER(buf as ArrayBuffer).result });
}

async function asRoot(slug: string, gen: Gen): Promise<TrustRoot> {
  return {
    slug,
    commonName: slug,
    orgName: `${slug} Org`,
    country: 'EC',
    pemContent: forge.pki.certificateToPem(gen.cert),
    fingerprintSha256: toHex(await digest('SHA-256', gen.der)),
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
    commonName: slug,
    rootSlug,
    orgName: `${slug} Org`,
    pemContent: forge.pki.certificateToPem(gen.cert),
    fingerprintSha256: toHex(await digest('SHA-256', gen.der)),
    validFrom: gen.cert.validity.notBefore.toISOString(),
    validUntil: gen.cert.validity.notAfter.toISOString(),
  } as TrustIntermediate;
}

const sameCert = (a: Certificate | undefined, b: Gen): boolean =>
  a !== undefined && toHex(new Uint8Array(a.toSchema().toBER(false))) === toHex(b.der);

// One PKI for the whole file — RSA keygen in node-forge is slow.
const root = makeCert({ cn: 'Synth Root', isCa: true, serial: '01' });
const interA = makeCert({ cn: 'Synth CA A', isCa: true, serial: '02', issuer: root });
const interB = makeCert({ cn: 'Synth CA B', isCa: true, serial: '03', issuer: root });
const leafA = makeCert({ cn: 'SIGNER A', isCa: false, serial: '10', issuer: interA });
const leafB = makeCert({ cn: 'SIGNER B', isCa: false, serial: '11', issuer: interB });
const forgedB = makeCert({
  cn: 'FORGED',
  isCa: false,
  serial: '12',
  issuer: interB,
  forgeIssuerDnOnly: true,
});

describe('validatePath validates the signer, whatever the pool order', () => {
  test('forged leaf with the real intermediate in the pool is rejected', async () => {
    const r = await validatePath(
      toPkijs(forgedB),
      [toPkijs(interB)],
      [await asRoot('synth', root)],
      new Date(),
    );
    expect(r.success).toBe(false);
    expect(r.matchedRoot).toBeUndefined();
  });

  test('multi-signature pool in production order (own CA, sibling leaf, own leaf) succeeds', async () => {
    const pool = [toPkijs(interB), toPkijs(leafA), toPkijs(leafB)];
    const r = await validatePath(toPkijs(leafB), pool, [await asRoot('synth', root)], new Date());
    expect(r.success, r.error).toBe(true);
    expect(r.matchedRoot?.slug).toBe('synth');
  });

  test('returned chain starts at the signer and its issuer is chain[1] (OCSP relies on it)', async () => {
    const pool = [toPkijs(interB), toPkijs(interA), toPkijs(leafA)];
    const r = await validatePath(toPkijs(leafB), pool, [await asRoot('synth', root)], new Date());
    expect(r.success, r.error).toBe(true);
    expect(sameCert(r.chain[0], leafB)).toBe(true);
    expect(sameCert(r.chain[1], interB)).toBe(true);
  });

  test('signer present twice in the pool still validates the signer', async () => {
    const pool = [toPkijs(leafB), toPkijs(interB), toPkijs(leafB)];
    const r = await validatePath(toPkijs(leafB), pool, [await asRoot('synth', root)], new Date());
    expect(r.success, r.error).toBe(true);
    expect(sameCert(r.chain[0], leafB)).toBe(true);
  });

  test('leaf whose keyUsage allows neither digitalSignature nor nonRepudiation is rejected', async () => {
    const encOnly = makeCert({
      cn: 'ENCRYPTION ONLY',
      isCa: false,
      serial: '13',
      issuer: interB,
      keyUsage: { keyEncipherment: true },
    });
    const r = await validatePath(
      toPkijs(encOnly),
      [toPkijs(interB)],
      [await asRoot('synth', root)],
      new Date(),
    );
    expect(r.success).toBe(false);
    expect(r.keyUsageNotSigning).toBe(true);
  });
});

describe('checkCertificate ("Validar certificado") validates the uploaded cert', () => {
  test('forged leaf bridged by the bundled intermediate is NOT trusted', async () => {
    const r = await checkCertificate(forgedB.der, [], {
      trustRoots: [await asRoot('synth', root)],
      trustIntermediates: [await asIntermediate('synth-ca-b', 'synth', interB)],
    });
    expect(r.trusted).toBe(false);
    expect(r.matchedAceSlug).toBeUndefined();
  });

  test('genuine leaf bridged by the bundled intermediate is trusted (control)', async () => {
    const r = await checkCertificate(leafB.der, [], {
      trustRoots: [await asRoot('synth', root)],
      trustIntermediates: [await asIntermediate('synth-ca-b', 'synth', interB)],
    });
    expect(r.trusted).toBe(true);
    expect(r.matchedAceSlug).toBe('synth');
  });
});
