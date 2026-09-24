import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { getTrustRoots } from '@firma-ec/tsl-ec';
import { beforeEach, describe, expect, test, vi } from 'vitest';

/**
 * revocation-verdict.test.ts — a revocation only defeats a signature if it
 * happened at or before the time the signature is PROVEN to exist
 * (2026-09-23 panel, Codex findings 2 and 4).
 *
 *  - Live OCSP used to turn ANY `revoked` into `invalid`. Once the chain fix
 *    gave OCSP the real issuer, genuine timestamped signatures of certs revoked
 *    LATER (holder left the company) would have flipped to invalid.
 *  - Embedded (DSS) revocation evidence only produced an `ltv_warning`: a
 *    signer revoked before signing could still come out `valid`.
 *
 * Crypto, chain, timestamp, OCSP and LTV are mocked: this pins the verdict
 * decision, not the parsers (those have their own tests).
 */

const FIX = resolve(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const SIGNED_AT = new Date('2026-06-01T12:00:00Z');
// Time the mocked timestamp claims; a test may move it.
const tsa = vi.hoisted(() => ({ time: new Date('2026-06-01T12:00:00Z') }));
// DSS the mocked extractor returns; undefined = the fixture's own (none).
const dss = vi.hoisted(() => ({ data: undefined as unknown }));
const DAY = 24 * 60 * 60 * 1000;

vi.mock('../src/integrity', async () => {
  const actual = await vi.importActual<typeof import('../src/integrity')>('../src/integrity');
  return {
    ...actual,
    verifySignatureValue: vi.fn(async () => true),
    checkDocumentIntegrity: vi.fn(async () => ({ matches: true, computed: new Uint8Array(32) })),
  };
});
vi.mock('../src/timestamp', async () => {
  const actual = await vi.importActual<typeof import('../src/timestamp')>('../src/timestamp');
  return {
    ...actual,
    verifyTimestamp: vi.fn(async (tstBytes: Uint8Array | undefined) =>
      tstBytes === undefined
        ? { present: false, valid: false, badge: 'none' }
        : { present: true, valid: true, badge: 'gold', signingTime: tsa.time },
    ),
  };
});
vi.mock('../src/pathValidation', () => ({
  validatePath: vi.fn(async (signer: unknown, _i: unknown, roots: { slug: string }[]) => ({
    success: true,
    chain: [signer, signer],
    matchedRoot: roots.find((r) => r.slug === 'argosdata'),
    warnings: [],
    chainIncomplete: false,
  })),
}));
vi.mock('../src/ocsp', () => ({ checkOcsp: vi.fn() }));
vi.mock('../src/dss', async () => {
  const actual = await vi.importActual<typeof import('../src/dss')>('../src/dss');
  return {
    ...actual,
    extractDss: vi.fn((bytes: Uint8Array) =>
      dss.data === undefined ? actual.extractDss(bytes) : { data: dss.data },
    ),
  };
});
vi.mock('../src/ltv', async () => {
  const actual = await vi.importActual<typeof import('../src/ltv')>('../src/ltv');
  return { ...actual, verifyLtv: vi.fn() };
});

const { verifyPdf } = await import('../src/index');
const pathMod = await import('../src/pathValidation');
const cmsMod = await import('../src/cms');
const ocspMod = await import('../src/ocsp');
const ltvMod = await import('../src/ltv');
const checkOcspMock = vi.mocked(ocspMod.checkOcsp);
const verifyLtvMock = vi.mocked(ltvMod.verifyLtv);

async function loadPdf(): Promise<Uint8Array> {
  return new Uint8Array(await readFile(resolve(FIX, 'eci-real-signed.pdf')));
}

/** Give the fixture's CMS a timestamp token so the live-OCSP path runs. */
function withTimestampToken(): void {
  const real = cmsMod.parseCms;
  vi.spyOn(cmsMod, 'parseCms').mockImplementation(async (c) => ({
    ...(await real(c)),
    timestampToken: new Uint8Array([1]),
  }));
}

const noLtv = {
  profile: 'B-T' as const,
  dssPresent: false,
  embeddedOcspCount: 0,
  embeddedCrlCount: 0,
  retrospectiveValid: false,
  errors: [],
};

beforeEach(async () => {
  vi.restoreAllMocks();
  tsa.time = SIGNED_AT;
  dss.data = undefined;
  checkOcspMock.mockReset();
  verifyLtvMock.mockReset();
  verifyLtvMock.mockResolvedValue(noLtv);
  // Sanity: the mocked chain needs a real ArgosData root in the bundle.
  expect((await getTrustRoots()).some((r) => r.slug === 'argosdata')).toBe(true);
});

describe('live OCSP revocation vs the timestamp-proven signing time', () => {
  test('revoked BEFORE the timestamp → invalid, cert_revoked', async () => {
    withTimestampToken();
    checkOcspMock.mockResolvedValue({
      status: 'revoked',
      source: 'live',
      checkedAt: new Date().toISOString(),
      revokedAt: new Date(SIGNED_AT.getTime() - DAY).toISOString(),
    });
    const r = await verifyPdf(await loadPdf());
    expect(checkOcspMock).toHaveBeenCalled();
    expect(r.status).toBe('invalid');
    expect(r.warnings.map((w) => w.code)).toContain('cert_revoked');
  });

  test('revoked AFTER the timestamp → not invalid, revoked_after_signing', async () => {
    withTimestampToken();
    checkOcspMock.mockResolvedValue({
      status: 'revoked',
      source: 'live',
      checkedAt: new Date().toISOString(),
      revokedAt: new Date(SIGNED_AT.getTime() + 30 * DAY).toISOString(),
    });
    const r = await verifyPdf(await loadPdf());
    expect(checkOcspMock).toHaveBeenCalled();
    expect(r.status).toBe('warning');
    expect(r.warnings.map((w) => w.code)).toContain('revoked_after_signing');
  });

  test('revoked with no revocation date → invalid (fail closed)', async () => {
    withTimestampToken();
    checkOcspMock.mockResolvedValue({
      status: 'revoked',
      source: 'live',
      checkedAt: new Date().toISOString(),
    });
    const r = await verifyPdf(await loadPdf());
    expect(r.status).toBe('invalid');
  });
});

describe('embedded (DSS) revocation evidence affects the verdict', () => {
  test('signer revoked before the timestamp per authenticated DSS evidence → invalid', async () => {
    withTimestampToken();
    verifyLtvMock.mockResolvedValue({
      ...noLtv,
      signerRevocation: { revokedAt: new Date(SIGNED_AT.getTime() - DAY) },
    });
    const r = await verifyPdf(await loadPdf());
    expect(r.status).toBe('invalid');
    expect(r.warnings.map((w) => w.code)).toContain('cert_revoked');
  });

  test('signer revoked after the timestamp per DSS evidence → warning, not invalid', async () => {
    withTimestampToken();
    verifyLtvMock.mockResolvedValue({
      ...noLtv,
      signerRevocation: { revokedAt: new Date(SIGNED_AT.getTime() + DAY) },
    });
    const r = await verifyPdf(await loadPdf());
    expect(r.status).toBe('warning');
    expect(r.warnings.map((w) => w.code)).toContain('revoked_after_signing');
  });
});

describe('timestamp added after the signer cert expired', () => {
  test('chain fails at the timestamp time but holds at the declared date → warning signing_time_unproven, not invalid', async () => {
    withTimestampToken();
    checkOcspMock.mockResolvedValue({
      status: 'good',
      source: 'live',
      checkedAt: new Date().toISOString(),
    });
    const roots = await getTrustRoots();
    const ok = (signer: unknown) => ({
      success: true,
      chain: [signer, signer],
      matchedRoot: roots.find((r) => r.slug === 'argosdata'),
      warnings: [],
      chainIncomplete: false,
    });
    // Timestamp applied now; the cert expired a day earlier, i.e. after any
    // date the fixture can declare.
    tsa.time = new Date();
    const expiredAt = tsa.time.getTime() - DAY;
    vi.mocked(pathMod.validatePath).mockImplementation(async (signer, _inter, _roots, at) =>
      at.getTime() < expiredAt
        ? (ok(signer) as Awaited<ReturnType<typeof pathMod.validatePath>>)
        : { success: false, chain: [], warnings: [], chainIncomplete: false, error: 'expired' },
    );
    const r = await verifyPdf(await loadPdf());
    expect(r.status).toBe('warning');
    expect(r.warnings.map((w) => w.code)).toContain('signing_time_unproven');
  });
});

describe('a trusted timestamp keeps an expired cert valid', () => {
  test('cert expired now, valid at the verified timestamp time → valid, no signing_time_unproven', async () => {
    withTimestampToken();
    checkOcspMock.mockResolvedValue({
      status: 'good',
      source: 'live',
      checkedAt: new Date().toISOString(),
    });
    const roots = await getTrustRoots();
    const expiredAt = SIGNED_AT.getTime() + DAY; // expired the day after the timestamp
    vi.mocked(pathMod.validatePath).mockImplementation(
      async (signer, _inter, _roots, at) =>
        (at.getTime() < expiredAt
          ? {
              success: true,
              chain: [signer, signer],
              matchedRoot: roots.find((r) => r.slug === 'argosdata'),
              warnings: [],
              chainIncomplete: false,
            }
          : {
              success: false,
              chain: [],
              warnings: [],
              chainIncomplete: false,
              error: 'expired',
            }) as Awaited<ReturnType<typeof pathMod.validatePath>>,
    );
    const r = await verifyPdf(await loadPdf());
    expect(r.status).toBe('valid');
    expect(r.warnings.map((w) => w.code)).not.toContain('signing_time_unproven');
    // Validated at the timestamp time, never at "now".
    expect(vi.mocked(pathMod.validatePath).mock.calls[0]?.[3]).toEqual(SIGNED_AT);
  });
});

describe('embedded DSS only replaces live OCSP when it authenticated something about the signer', () => {
  const garbageDss = { certs: [], ocsps: [new Uint8Array([0x30, 0x00])], crls: [], vri: {} };

  test('DSS bytes without authenticated signer evidence do not suppress live OCSP', async () => {
    withTimestampToken();
    dss.data = garbageDss;
    verifyLtvMock.mockResolvedValue({ ...noLtv, dssPresent: true, profile: 'B-LT' });
    checkOcspMock.mockResolvedValue({
      status: 'revoked',
      source: 'live',
      checkedAt: new Date().toISOString(),
      revokedAt: new Date(SIGNED_AT.getTime() - DAY).toISOString(),
    });
    const r = await verifyPdf(await loadPdf());
    expect(checkOcspMock).toHaveBeenCalled();
    expect(r.status).toBe('invalid');
  });

  test('authenticated signer evidence in the DSS → live OCSP skipped (control)', async () => {
    withTimestampToken();
    dss.data = garbageDss;
    verifyLtvMock.mockResolvedValue({
      ...noLtv,
      dssPresent: true,
      profile: 'B-LT',
      signerEvidence: true,
    });
    const r = await verifyPdf(await loadPdf());
    expect(checkOcspMock).not.toHaveBeenCalled();
    expect(r.status).toBe('valid');
  });

  test('embedded scan cut short, nothing authenticated, live OCSP inconclusive → warning revocation_unchecked', async () => {
    withTimestampToken();
    dss.data = garbageDss;
    verifyLtvMock.mockResolvedValue({
      ...noLtv,
      dssPresent: true,
      profile: 'B-LT',
      revocationIncomplete: true,
    });
    checkOcspMock.mockResolvedValue({
      status: 'unknown',
      source: 'live',
      checkedAt: new Date().toISOString(),
    });
    const r = await verifyPdf(await loadPdf());
    expect(r.status).toBe('warning');
    expect(r.warnings.map((w) => w.code)).toContain('revocation_unchecked');
  });

  test('a CA of the chain revoked before the timestamp (authenticated DSS) → invalid', async () => {
    withTimestampToken();
    verifyLtvMock.mockResolvedValue({
      ...noLtv,
      caRevocation: { revokedAt: new Date(SIGNED_AT.getTime() - DAY) },
    });
    checkOcspMock.mockResolvedValue({
      status: 'good',
      source: 'live',
      checkedAt: new Date().toISOString(),
    });
    const r = await verifyPdf(await loadPdf());
    expect(r.status).toBe('invalid');
    expect(r.warnings.map((w) => w.code)).toContain('cert_revoked');
  });

  test('check cut short and live OCSP not reachable (not_checked) → warning revocation_unchecked', async () => {
    withTimestampToken();
    dss.data = garbageDss;
    verifyLtvMock.mockResolvedValue({
      ...noLtv,
      dssPresent: true,
      profile: 'B-LT',
      revocationIncomplete: true,
    });
    checkOcspMock.mockResolvedValue({
      status: 'not_checked',
      source: 'none',
      checkedAt: new Date().toISOString(),
    });
    const r = await verifyPdf(await loadPdf());
    expect(r.status).toBe('warning');
    expect(r.warnings.map((w) => w.code)).toContain('revocation_unchecked');
  });

  test('embedded evidence found but the scan was incomplete → never valid', async () => {
    withTimestampToken();
    dss.data = garbageDss;
    verifyLtvMock.mockResolvedValue({
      ...noLtv,
      dssPresent: true,
      profile: 'B-LT',
      signerEvidence: true,
      revocationIncomplete: true,
    });
    checkOcspMock.mockResolvedValue({
      status: 'not_checked',
      source: 'none',
      checkedAt: new Date().toISOString(),
    });
    const r = await verifyPdf(await loadPdf());
    expect(r.status).toBe('warning');
    expect(r.warnings.map((w) => w.code)).toContain('revocation_unchecked');
  });
});

describe('round 9: a signer answer does not settle unchecked CA links (Codex)', () => {
  const garbage = { certs: [], ocsps: [new Uint8Array([0x30, 0x00])], crls: [], vri: {} };
  test('CA-link material skipped + live signer OCSP good -> warning revocation_unchecked', async () => {
    withTimestampToken();
    dss.data = garbage;
    verifyLtvMock.mockResolvedValue({
      ...noLtv,
      dssPresent: true,
      profile: 'B-LT',
      revocationIncomplete: true,
      caRevocationIncomplete: true,
    });
    checkOcspMock.mockResolvedValue({
      status: 'good',
      source: 'live',
      checkedAt: new Date().toISOString(),
    });
    const r = await verifyPdf(await loadPdf());
    expect(r.status).toBe('warning');
    expect(r.warnings.map((w) => w.code)).toContain('revocation_unchecked');
  });

  test('only signer-link material skipped + live signer OCSP good -> settled (control)', async () => {
    withTimestampToken();
    dss.data = garbage;
    verifyLtvMock.mockResolvedValue({
      ...noLtv,
      dssPresent: true,
      profile: 'B-LT',
      revocationIncomplete: true,
    });
    checkOcspMock.mockResolvedValue({
      status: 'good',
      source: 'live',
      checkedAt: new Date().toISOString(),
    });
    const r = await verifyPdf(await loadPdf());
    expect(r.warnings.map((w) => w.code)).not.toContain('revocation_unchecked');
  });
});
