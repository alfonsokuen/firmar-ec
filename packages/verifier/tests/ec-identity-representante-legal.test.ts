import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ecCertIdentity, subjectInfo } from '@firma-ec/crypto-core';
import { Constructed, ObjectIdentifier, Sequence, Utf8String } from 'asn1js';
import { Certificate, ContentInfo, Extension, SignedData } from 'pkijs';
import { describe, expect, it } from 'vitest';
import { checkCertificate } from '../src/certCheck';

const FIXTURES = join(import.meta.dirname, 'fixtures');

/**
 * A legal-representative certificate identifies TWO parties: the natural
 * person who holds the key and the company they sign for. FirmaEC 5.1.0 shows
 * the company's RUC, its razón social and the holder's cargo; firmar.ec showed
 * only the holder, so a counterparty could not tell a personal signature from
 * one binding a company.
 *
 * Every ACE publishes the pair under its own arc with the same suffixes —
 * confirmed against real ArgosData and Security Data certificates:
 *   .5  → cargo            (REPRESENTANTE LEGAL, GERENTE GENERAL, …)
 *   .10 → razón social
 *   .11 → the company's RUC (not the holder's)
 *
 * As elsewhere in this suite, the assertions are on shape and provenance so no
 * personal datum from the fixtures is written into the repository.
 */

const ARGOSDATA_ARC = '1.3.6.1.4.1.59198.3';
const UANATACA_ARC = '1.3.6.1.4.1.47286.102.3';

const SUBJECT_ALT_NAME_OID = '2.5.29.17';
const OTHER_NAME_TYPE = 0;
const CONTEXT_SPECIFIC = 3;

/** Certificate carrying only an ACE arc's attributes, as top-level extensions. */
function certWithAceArc(arc: string, attrs: Record<string, string>): Certificate {
  const cert = new Certificate();
  cert.extensions = Object.entries(attrs).map(
    ([suffix, value]) =>
      new Extension({
        extnID: `${arc}.${suffix}`,
        critical: false,
        extnValue: new Utf8String({ value }).toBER(false),
      }),
  );
  return cert;
}

/**
 * Certificate carrying the arc's attributes nested in subjectAltName as
 * `otherName` entries — the placement Uanataca and ICERT-EC use.
 *
 *   SubjectAltName ::= SEQUENCE OF GeneralName
 *   otherName      ::= [0] IMPLICIT SEQUENCE { type-id OBJECT IDENTIFIER,
 *                                              value [0] EXPLICIT ANY }
 *
 * Hand-rolled in DER rather than via pkijs' `GeneralNames`, which drops
 * `otherName` entries on serialisation and would silently produce an empty
 * SAN — a test that passes against nothing.
 */
function certWithAceArcInSan(arc: string, attrs: Record<string, string>): Certificate {
  const otherNames = Object.entries(attrs).map(
    ([suffix, value]) =>
      new Constructed({
        idBlock: { tagClass: CONTEXT_SPECIFIC, tagNumber: OTHER_NAME_TYPE },
        value: [
          new ObjectIdentifier({ value: `${arc}.${suffix}` }),
          new Constructed({
            idBlock: { tagClass: CONTEXT_SPECIFIC, tagNumber: 0 },
            value: [new Utf8String({ value })],
          }),
        ],
      }),
  );

  // Round-trip through DER: pkijs only fills `parsedValue` when the extension
  // comes off the wire, which is how it reaches the code in production.
  const der = new Extension({
    extnID: SUBJECT_ALT_NAME_OID,
    critical: false,
    extnValue: new Sequence({ value: otherNames }).toBER(false),
  })
    .toSchema()
    .toBER(false);

  const cert = new Certificate();
  cert.extensions = [Extension.fromBER(der)];
  return cert;
}

/** Leaf certificates issued by `issuerSubstring`, across all signatures. */
function leavesFrom(fixture: string, issuerSubstring: string): Certificate[] {
  const pdf = readFileSync(join(FIXTURES, fixture));
  const text = pdf.toString('latin1');
  const out: Certificate[] = [];
  const re = /\/Contents\s*<([0-9A-Fa-f\s]+)>/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(text)) !== null) {
    const hex = match[1]!.replace(/\s/g, '').replace(/(00)+$/, '');
    if (hex.length < 200) continue;
    const blob = Buffer.from(hex.length % 2 ? hex.slice(0, -1) : hex, 'hex');
    let signed: SignedData;
    try {
      signed = new SignedData({ schema: ContentInfo.fromBER(blob).content });
    } catch {
      continue;
    }
    for (const cert of signed.certificates ?? []) {
      if (!(cert instanceof Certificate)) continue;
      const isCa =
        cert.extensions?.some(
          (e) =>
            e.extnID === '2.5.29.19' &&
            (e.parsedValue as { cA?: boolean } | undefined)?.cA === true,
        ) ?? false;
      if (isCa) continue;
      const issuerCn = cert.issuer.typesAndValues.find((t) => t.type === '2.5.4.3');
      if (String(issuerCn?.value.valueBlock.value ?? '').includes(issuerSubstring)) out.push(cert);
    }
  }
  return out;
}

describe('ecCertIdentity — legal representative', () => {
  it('Security Data: reads cargo and razón social from the real arc', () => {
    const leaves = [
      ...leavesFrom('eci-real-contrato2026.pdf', 'SECURITY DATA'),
      ...leavesFrom('eci-real-lideres.pdf', 'SECURITY DATA'),
    ];
    expect(leaves.length).toBeGreaterThan(0);

    for (const cert of leaves) {
      const identity = ecCertIdentity(cert);
      expect(identity.ace).toBe('Security Data');

      expect(identity.jobTitle).toBeTruthy();
      expect(identity.organization).toBeTruthy();

      // The company RUC, not the holder's: it does NOT start with the cédula.
      expect(identity.ruc).toMatch(/^\d{13}$/);
      expect(identity.ruc!.startsWith(identity.cedula!)).toBe(false);

      // Security Data writes its OWN name into the subject `O` RDN. Publishing
      // that as the razón social would attribute the issuer to the holder —
      // which is why `organization` has no DN fallback.
      expect(identity.organization).not.toBe(subjectInfo(cert).raw['O']);
    }
  });

  it('ArgosData: same suffixes, extensions at top level instead of the SAN', () => {
    const identity = ecCertIdentity(
      certWithAceArc(ARGOSDATA_ARC, {
        '1': '1700000001',
        '2': 'NOMBRE UNO',
        '3': 'APELLIDO',
        '4': 'SEGUNDO',
        '5': 'REPRESENTANTE LEGAL',
        '10': 'EMPRESA DEMO S.A.S.',
        '11': '1791234567001',
      }),
    );

    expect(identity.ace).toBe('ArgosData');
    expect(identity.cedula).toBe('1700000001');
    expect(identity.jobTitle).toBe('REPRESENTANTE LEGAL');
    expect(identity.organization).toBe('EMPRESA DEMO S.A.S.');
    expect(identity.ruc).toBe('1791234567001');
  });

  it('Uanataca: reads cargo and razón social nested inside subjectAltName', () => {
    // Real shape of a Uanataca legal-representative certificate: the same
    // suffixes as ArgosData, but published as SAN otherName entries instead of
    // top-level extensions. Both placements must reach the same fields — the
    // top-level test alone would leave this path unexercised.
    const identity = ecCertIdentity(
      certWithAceArcInSan(UANATACA_ARC, {
        '1': '1700000001',
        '2': 'NOMBRE',
        '3': 'APELLIDO',
        '4': 'SEGUNDO',
        '5': 'GERENTE GENERAL',
        '10': 'EMPRESA DEMO S.A.S.',
        '11': '1791234567001',
        // The certificate TYPE, which is not the cargo: a holder whose cargo
        // reads GERENTE GENERAL can still hold a "REPRESENTANTE LEGAL" cert.
        '50': 'REPRESENTANTE LEGAL',
      }),
    );

    expect(identity.ace).toBe('Uanataca');
    expect(identity.cedula).toBe('1700000001');
    expect(identity.jobTitle).toBe('GERENTE GENERAL');
    expect(identity.organization).toBe('EMPRESA DEMO S.A.S.');
    expect(identity.ruc).toBe('1791234567001');
  });

  it('leaves both fields undefined on a natural-person certificate', () => {
    // No .5 / .10 issued — the UI must render nothing, never an empty row.
    const identity = ecCertIdentity(
      certWithAceArc(ARGOSDATA_ARC, { '1': '1700000001', '11': '1700000001001' }),
    );

    expect(identity.jobTitle).toBeUndefined();
    expect(identity.organization).toBeUndefined();
    expect(identity.ruc).toBe('1700000001001');
  });

  it('checkCertificate surfaces the fields the page renders', async () => {
    // The page binds `result.jobTitle` / `result.organization`, so asserting on
    // ecCertIdentity alone would not catch an unwired CertCheckResult field.
    const certDer = new Uint8Array(readFileSync(join(FIXTURES, 'leaf-bce.der')));
    const result = await checkCertificate(certDer, [], {
      trustRoots: [],
      atTime: new Date('2026-01-01T00:00:00Z'),
    });

    // A natural-person leaf: the keys must exist on the type and stay absent.
    expect(result.jobTitle).toBeUndefined();
    expect(result.organization).toBeUndefined();
    expect(result.ruc).toMatch(/^\d{13}$/);
  });
});
