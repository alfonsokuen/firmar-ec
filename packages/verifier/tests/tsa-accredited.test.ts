import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { toHex } from '@firma-ec/crypto-core';
import { validateTsaCertChain } from '@firma-ec/tsa-trust';
import { fromBER } from 'asn1js';
import forge from 'node-forge';
import { Certificate } from 'pkijs';
import { describe, expect, test } from 'vitest';
import { accreditedTsaAnchors } from '../src/timestamp';

/**
 * tsa-accredited.test.ts — timestamps from any ARCOTEL-accredited ECI are
 * recognised (2026-09-24, "a la par de Security Data").
 *
 * Before, only FreeTSA and the UANATACA ROOT 2016 anchors were trusted for
 * timestamps; a Security Data, BCE or UANATACA EC TSU01 timestamp failed with
 * chain_invalid, so it could not serve as proof of the signing time. The
 * verifier now offers the TSL roots it already pins for signatures.
 */

const derOf = (u8: Uint8Array) => new Certificate({ schema: fromBER(u8.slice().buffer).result });
const sha256Hex = async (c: Certificate) =>
  toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', c.toSchema().toBER(false))));

describe('accredited TSA anchors come from the ARCOTEL TSL', () => {
  test('include the Security Data CA-2 root and the SubCA-2 that issues its TSU', async () => {
    const { anchors, intermediates } = await accreditedTsaAnchors();
    const anchorFps = await Promise.all(anchors.map(sha256Hex));
    // Fingerprint published by Security Data (sellado_tiempo.pdf, SD-ID-PE-12).
    expect(anchorFps).toContain('503b5960fa8cc58f3367642a911fd8f8277e474d6891637fe56ca2a69f069cbd');
    const cns = intermediates.map(
      (c) =>
        (
          c.subject.typesAndValues.find((t) => t.type === '2.5.4.3')?.value.valueBlock as {
            value: string;
          }
        ).value,
    );
    expect(cns).toContain('AUTORIDAD DE CERTIFICACION SUBCA-2 SECURITY DATA');
  });

  test('the official UANATACA EC TSU01 certificate validates against them', async () => {
    const der = new Uint8Array(
      readFileSync(
        resolve(__dirname, '../../tsa-trust/tests/__fixtures__/uanataca-ec-tsu01-leaf.der'),
      ),
    );
    const cert = derOf(der);
    const r = await validateTsaCertChain(
      { certificate: cert, der, notBefore: cert.notBefore.value, notAfter: cert.notAfter.value },
      [],
      new Date(),
      await accreditedTsaAnchors(),
    );
    expect(r).toMatchObject({ ok: true });
  });
});

describe('RFC 3161 §2.3: a TSA cert carries timeStamping as its ONLY extended key usage, critical', () => {
  // With the ARCOTEL roots now anchoring timestamps, a lax EKU check would let
  // any accredited-CA cert that merely includes timeStamping mint timestamps
  // (Codex + Opus, 2026-09-24). The four real TSU certs checked meet the rule.
  const YEAR = 365 * 24 * 60 * 60 * 1000;
  const root = (() => {
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const c = forge.pki.createCertificate();
    c.publicKey = keys.publicKey;
    c.serialNumber = '01';
    c.validity.notBefore = new Date(Date.now() - YEAR);
    c.validity.notAfter = new Date(Date.now() + 5 * YEAR);
    c.setSubject([{ name: 'commonName', value: 'Synth Accredited Root' }]);
    c.setIssuer(c.subject.attributes);
    c.setExtensions([
      { name: 'basicConstraints', cA: true },
      { name: 'keyUsage', keyCertSign: true, cRLSign: true },
    ]);
    c.sign(keys.privateKey, forge.md.sha256.create());
    return { c, keys };
  })();
  const toPkijs = (c: forge.pki.Certificate) => {
    const der = Uint8Array.from(forge.asn1.toDer(forge.pki.certificateToAsn1(c)).getBytes(), (x) =>
      x.charCodeAt(0),
    );
    return { der, cert: derOf(der) };
  };
  const tsa = (serial: string, eku: Record<string, unknown>) => {
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const c = forge.pki.createCertificate();
    c.publicKey = keys.publicKey;
    c.serialNumber = serial;
    c.validity.notBefore = new Date(Date.now() - YEAR);
    c.validity.notAfter = new Date(Date.now() + YEAR);
    c.setSubject([{ name: 'commonName', value: `TSA ${serial}` }]);
    c.setIssuer(root.c.subject.attributes);
    c.setExtensions([
      { name: 'basicConstraints', cA: false },
      { name: 'extKeyUsage', ...eku },
    ]);
    c.sign(root.keys.privateKey, forge.md.sha256.create());
    return toPkijs(c);
  };
  const check = async (t: { der: Uint8Array; cert: Certificate }) =>
    validateTsaCertChain(
      {
        certificate: t.cert,
        der: t.der,
        notBefore: t.cert.notBefore.value,
        notAfter: t.cert.notAfter.value,
      },
      [],
      new Date(),
      { anchors: [toPkijs(root.c).cert], intermediates: [] },
    );

  test('only timeStamping, critical -> accepted (control)', async () => {
    expect(await check(tsa('10', { critical: true, timeStamping: true }))).toMatchObject({
      ok: true,
    });
  });

  test('timeStamping shared with clientAuth -> rejected', async () => {
    const r = await check(tsa('11', { critical: true, timeStamping: true, clientAuth: true }));
    expect(r).toMatchObject({ ok: false, reason: 'tsa_eku_missing' });
  });

  test('timeStamping but non-critical -> rejected', async () => {
    const r = await check(tsa('12', { critical: false, timeStamping: true }));
    expect(r).toMatchObject({ ok: false, reason: 'tsa_eku_missing' });
  });
});
