import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fromBER } from 'asn1js';
import { Certificate } from 'pkijs';
import { describe, expect, it } from 'vitest';
import { parseTimestampToken } from '../../tsa-client/src/parseToken';
import { parseTimeStampResp } from '../../tsa-client/src/response';
import {
  type ParsedCertLike,
  findTsaRootByIssuerCN,
  getTsaTrustRoots,
  validateTsaCertChain,
} from '../src/index';

const FIXTURE_TSR = resolve(
  __dirname,
  '../../tsa-client/tests/__fixtures__/freetsa-kat-2026-05-09.tsr',
);
const HAS_KAT = existsSync(FIXTURE_TSR);

// 2026-08-06 — the TSA leaf cert ("Sello de tiempo electrónico de UANATACA -
// TSU01") extracted from a real signed contract (both signatures carried the
// same token, leaf-only — no intermediate embedded). See intermediates.ts
// for the forensic-extraction + AIA-refetch provenance of the bundled
// UANATACA CA1 2021 intermediate this test exercises.
const FIXTURE_UANATACA_TSU01 = resolve(__dirname, '__fixtures__/uanataca-tsu01-leaf.der');
// Public TSA certificate of MINTEL's accredited timestamping unit (a service
// cert, no personal data), issued by UANATACA CA2 2021.
const FIXTURE_MINTEL_TSU02 = resolve(__dirname, '__fixtures__/mintel-tsu02-leaf.der');

function derToCert(der: Uint8Array): ParsedCertLike {
  const ab = der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength) as ArrayBuffer;
  const asn = fromBER(ab);
  if (asn.offset === -1) throw new Error('cert decode failed');
  const cert = new Certificate({ schema: asn.result });
  return {
    certificate: cert,
    der,
    notBefore: cert.notBefore.value as Date,
    notAfter: cert.notAfter.value as Date,
  };
}

describe('getTsaTrustRoots', () => {
  it('returns 3 entries with FreeTSA + UANATACA real + ARCOTEL placeholder', () => {
    const roots = getTsaTrustRoots();
    expect(roots).toHaveLength(3);
    const slugs = roots.map((r) => r.slug).sort();
    expect(slugs).toEqual(['arcotel-placeholder', 'freetsa', 'uanataca']);

    const freetsa = roots.find((r) => r.slug === 'freetsa')!;
    expect(freetsa.isPlaceholder).toBe(false);
    expect(freetsa.notBefore).toBeInstanceOf(Date);
    expect(freetsa.notAfter).toBeInstanceOf(Date);
    expect(freetsa.certDer.byteLength).toBeGreaterThan(0);

    const placeholder = roots.find((r) => r.slug === 'arcotel-placeholder')!;
    expect(placeholder.isPlaceholder).toBe(true);
  });

  it('caches the result across calls', () => {
    const a = getTsaTrustRoots();
    const b = getTsaTrustRoots();
    expect(a).toBe(b);
  });
});

describe('findTsaRootByIssuerCN', () => {
  it('returns the FreeTSA root when its CN matches', () => {
    const roots = getTsaTrustRoots();
    const freetsa = roots.find((r) => r.slug === 'freetsa')!;
    // Subject CN of FreeTSA root cert
    const subjectCN = (
      freetsa.certificate.subject.typesAndValues as unknown as {
        type: string;
        value: { valueBlock: { value: string } };
      }[]
    ).find((tv) => tv.type === '2.5.4.3')?.value.valueBlock.value;
    expect(subjectCN).toBeTruthy();
    const match = findTsaRootByIssuerCN(subjectCN as string);
    expect(match?.slug).toBe('freetsa');
  });

  it('returns null when no root matches', () => {
    expect(findTsaRootByIssuerCN('nonexistent CN')).toBeNull();
  });
});

describe('validateTsaCertChain', () => {
  it.skipIf(!HAS_KAT)('validates the FreeTSA-issued TSA cert from the KAT fixture', async () => {
    const tsr = new Uint8Array(readFileSync(FIXTURE_TSR));
    const { token } = parseTimeStampResp(tsr);
    const parsed = parseTimestampToken(token);
    expect(parsed.tsaCertDers.length).toBeGreaterThanOrEqual(1);
    const tsaCert = derToCert(parsed.tsaCertDers[0]!);
    // Extra intermediates from token (skip the leaf)
    const intermediates = parsed.tsaCertDers.slice(1).map((d) => derToCert(d).certificate);
    const result = await validateTsaCertChain(tsaCert, intermediates);
    expect(result.ok).toBe(true);
    expect(result.matchedRoot?.slug).toBe('freetsa');
  });

  it('validates the real UANATACA TSU01 leaf against the bundled CA1 2021 intermediate, even with zero caller-supplied intermediates (token ships leaf-only)', async () => {
    const der = new Uint8Array(readFileSync(FIXTURE_UANATACA_TSU01));
    const tsaCert = derToCert(der);
    // Empty array on purpose — mirrors the real token, which embeds only the
    // leaf. Before the 2026-08-06 fix this returned `chain_invalid`: the
    // package had no UANATACA root/intermediate at all.
    const result = await validateTsaCertChain(tsaCert, []);
    expect(result).toMatchObject({ ok: true });
    expect(result.matchedRoot?.slug).toBe('uanataca');
  });

  it('validates the real MINTEL TSU02 leaf (issued by UANATACA CA2 2021) from a leaf-only token', async () => {
    // Real case 2026-09-23: a UANATACA-signed contract carried a MINTEL TSU02
    // timestamp and firmar.ec showed it as `timestamp_invalid (chain_invalid)`
    // because only CA1 2021 was bundled for TSAs.
    const tsaCert = derToCert(new Uint8Array(readFileSync(FIXTURE_MINTEL_TSU02)));
    const result = await validateTsaCertChain(tsaCert, []);
    expect(result).toMatchObject({ ok: true });
    expect(result.matchedRoot?.slug).toBe('uanataca');
  });

  it('rejects with tsa_eku_missing when EKU is absent', async () => {
    // Use the FreeTSA root cert itself as the "TSA cert" — the root has no
    // id-kp-timeStamping EKU, so the check must fail early.
    const root = getTsaTrustRoots().find((r) => r.slug === 'freetsa')!;
    const result = await validateTsaCertChain(
      {
        certificate: root.certificate,
        der: root.certDer,
        notBefore: root.notBefore,
        notAfter: root.notAfter,
      },
      [],
    );
    expect(result).toMatchObject({ ok: false, reason: 'tsa_eku_missing' });
  });

  it.skipIf(!HAS_KAT)('rejects with reason:expired when atTime is past notAfter', async () => {
    const tsr = new Uint8Array(readFileSync(FIXTURE_TSR));
    const { token } = parseTimeStampResp(tsr);
    const parsed = parseTimestampToken(token);
    const tsaCert = derToCert(parsed.tsaCertDers[0]!);
    const future = new Date(tsaCert.notAfter.getTime() + 24 * 3600 * 1000);
    const result = await validateTsaCertChain(tsaCert, [], future);
    expect(result).toMatchObject({ ok: false, reason: 'expired' });
  });
});
