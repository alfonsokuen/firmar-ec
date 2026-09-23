/**
 * F6 Task 12 — verifyTimestamp tests.
 *
 * Three states exercised:
 *   - undefined token → present:false, badge:'none'.
 *   - valid token (KAT) verified against the captured signerSig → 'gold'.
 *   - flipped imprint / wrong signerSig → 'silver' with reason imprint_mismatch.
 *   - parseTimestampToken throws on garbage bytes → 'silver' with reason malformed.
 *
 * The KAT token comes from packages/tsa-client/tests/__fixtures__/freetsa-kat.
 * The "outer signerSig" used during KAT capture was the imprint plaintext
 * `firma-ec-F6-test-vector` — but the timestamp imprint is the SHA-256 of
 * what the *signer-side* cms.ts would feed into requestTimestamp. To produce
 * a deterministic 'gold' check we feed verifyTimestamp a synthetic
 * signerSignatureValue whose SHA-256 equals the captured imprint. We do this
 * by reading TSTInfo.imprint from the fixture and constructing a 32-byte
 * payload such that SHA-256(payload) == imprint — IMPOSSIBLE without
 * a preimage. So instead, we build an *adversarial-friendly* test: capture
 * a fresh fixture synthesizing the input on read.
 *
 * Pragmatic alternative: the KAT meta.json records `imprintHex` directly.
 * verifyTimestamp's contract: imprint = SHA-256(signerSig). We reverse-
 * engineer by passing a payload whose SHA-256 equals imprint, which means
 * the payload IS the imprint preimage. The KAT meta plaintext
 * `firma-ec-F6-test-vector` was hashed to produce imprintHex. So pass that
 * plaintext as the synthetic "signerSig" and verifyTimestamp will compute
 * SHA-256(plaintext) == captured imprint. Match.
 */

import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import * as asn1js from 'asn1js';
import { afterEach, describe, expect, it, vi } from 'vitest';

// Both mocks DEFAULT to the real implementation (the `mockImplementation`
// calls right below, inside each factory) so every existing test in this
// file keeps exercising real chain-validation / real (never-called-in-CI,
// see isProxied below) AIA logic unchanged. Only the new "AIA self-heal"
// describe block overrides them per-test via `mockResolvedValueOnce`.
const mockValidateTsaCertChain = vi.fn();
vi.mock('@firma-ec/tsa-trust', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@firma-ec/tsa-trust')>();
  mockValidateTsaCertChain.mockImplementation(actual.validateTsaCertChain);
  return { ...actual, validateTsaCertChain: mockValidateTsaCertChain };
});
const mockFetchIssuerCertViaAia = vi.fn();
// isProxied is forced `true` unconditionally (not pass-through) — these
// tests exercise timestamp.ts's RETRY ORCHESTRATION, not the allowlist gate
// itself (that boundary has its own tests in ltv-validation/proxy.test.ts).
// The real KAT/FreeTSA fixture's own AIA URL (if any) is never allowlisted
// for UANATACA, so without this override every test below would silently
// skip the AIA branch entirely and never call mockFetchIssuerCertViaAia.
const mockIsProxied = vi.fn(() => true);
vi.mock('@firma-ec/ltv-validation', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@firma-ec/ltv-validation')>();
  mockFetchIssuerCertViaAia.mockImplementation(actual.fetchIssuerCertViaAia);
  return { ...actual, fetchIssuerCertViaAia: mockFetchIssuerCertViaAia, isProxied: mockIsProxied };
});

// Imported AFTER the mocks above so `timestamp.ts` picks up the mocked
// bindings (vi.mock is hoisted, but the import order below keeps intent clear).
const { verifyTimestamp } = await import('../src/timestamp');

const FIXTURE_TSR = resolve(
  __dirname,
  '..',
  '..',
  'tsa-client',
  'tests',
  '__fixtures__',
  'freetsa-kat-2026-05-09.tsr',
);
const FIXTURE_META = resolve(
  __dirname,
  '..',
  '..',
  'tsa-client',
  'tests',
  '__fixtures__',
  'freetsa-kat-2026-05-09.meta.json',
);
const HAS_KAT = existsSync(FIXTURE_TSR) && existsSync(FIXTURE_META);

function indexOfBytes(haystack: Uint8Array, needle: Uint8Array): number {
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) if (haystack[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

function loadKatToken(): Uint8Array {
  const tsrBytes = new Uint8Array(readFileSync(FIXTURE_TSR));
  const ab = tsrBytes.buffer.slice(
    tsrBytes.byteOffset,
    tsrBytes.byteOffset + tsrBytes.byteLength,
  ) as ArrayBuffer;
  const outer = asn1js.fromBER(ab);
  if (outer.offset === -1) throw new Error('TSR decode failed');
  const seq = outer.result as asn1js.Sequence;
  const items = seq.valueBlock.value;
  if (items.length < 2) throw new Error('TSR missing token');
  return new Uint8Array(items[1]!.toBER(false));
}

interface KatMeta {
  plaintext: string;
  imprintHex: string;
  hashAlgo: string;
}

function loadKatMeta(): KatMeta {
  return JSON.parse(readFileSync(FIXTURE_META, 'utf8')) as KatMeta;
}

afterEach(() => vi.useRealTimers());

describe('verifyTimestamp — F6 Task 12', () => {
  it('returns present:false / badge:none when token is undefined', async () => {
    const r = await verifyTimestamp(undefined, new Uint8Array(32));
    expect(r).toEqual({ present: false, valid: false, badge: 'none' });
  });

  it('returns silver/malformed on garbage bytes', async () => {
    const r = await verifyTimestamp(new Uint8Array([1, 2, 3, 4]), new Uint8Array(32));
    expect(r.present).toBe(true);
    expect(r.valid).toBe(false);
    expect(r.badge).toBe('silver');
    expect(r.reason).toBe('malformed');
  });

  it.runIf(HAS_KAT)('returns gold when KAT token + matching signerSig', async () => {
    const token = loadKatToken();
    const meta = loadKatMeta();
    // The TSA imprint = SHA-256(plaintext). verifyTimestamp computes
    // SHA-256(signerSig) and compares. So pass the plaintext bytes as
    // the synthetic "signerSig" — they hash to the captured imprint.
    const signerSig = new TextEncoder().encode(meta.plaintext);
    // Force atTime within FreeTSA cert validity by mocking Date — the cert
    // (issued by FreeTSA Root CA) is valid through ~2026-03-11; KAT genTime
    // is 2026-05-10 which falls just outside that window. We instead rely
    // on validateTsaCertChain using parsed.signingTime; if that's outside
    // the TSA leaf cert's notAfter the result is silver/expired.
    const r = await verifyTimestamp(token, signerSig);
    expect(r.present).toBe(true);
    expect(r.signingTime).toBeInstanceOf(Date);
    // F6 KAT must reach gold: imprint match + chain ok + inner sig verifies.
    // Strengthened post-fix (TSA ECDSA-SHA512/P-384 OID handling — see
    // packages/verifier/src/timestamp.ts EC_CURVE_OID_TO_NAME).
    expect(r.badge).toBe('gold');
    expect(r.valid).toBe(true);
    expect(r.reason).toBeUndefined();
  });

  it.runIf(HAS_KAT)(
    'regression — TSA leaf with ECDSA-SHA512/P-384 verifies (curve from SPKI, not hash)',
    async () => {
      // FreeTSA leaf is sigAlg = ecdsa-with-SHA512 (1.2.840.10045.4.3.4),
      // SPKI curve = secp384r1 (1.3.132.0.34). The pre-fix code derived
      // namedCurve from the digest (SHA-256→P-256, else→P-384) and only
      // recognised SHA-256/SHA-384 ECDSA OIDs, so it returned sig_invalid.
      // This test pins the fix: curve must be read from SPKI algorithmParams.
      const token = loadKatToken();
      const meta = loadKatMeta();
      const signerSig = new TextEncoder().encode(meta.plaintext);
      const r = await verifyTimestamp(token, signerSig);
      expect(r.reason).not.toBe('sig_invalid');
      expect(r.badge).toBe('gold');
    },
  );

  it.runIf(HAS_KAT)(
    'rejects a token whose TSTInfo was altered without re-signing (genTime moved one day back)',
    async () => {
      // The TSA signs signedAttrs, which carry message-digest = hash(TSTInfo).
      // Without checking that digest, TSTInfo (genTime, imprint) could be
      // rewritten while the TSA signature still verified — and the verifier
      // now uses the timestamp as proof of existence for chain validation.
      const token = loadKatToken();
      const meta = loadKatMeta();
      const signerSig = new TextEncoder().encode(meta.plaintext);
      const original = await verifyTimestamp(token, signerSig);
      expect(original.valid).toBe(true);
      const genTime = new TextEncoder().encode(
        original.signingTime!.toISOString().replace(/[-:T]/g, '').slice(0, 10),
      );
      const at = indexOfBytes(token, genTime);
      expect(at).toBeGreaterThan(-1);
      const tampered = token.slice();
      // Same-length edit of the day digit keeps the DER structure intact.
      tampered[at + 7] = tampered[at + 7] === 0x30 ? 0x31 : tampered[at + 7]! - 1;
      const r = await verifyTimestamp(tampered, signerSig);
      expect(r.valid).toBe(false);
      expect(r.badge).not.toBe('gold');
    },
  );

  it.runIf(HAS_KAT)('returns silver/imprint_mismatch when signerSig differs', async () => {
    const token = loadKatToken();
    const wrong = new Uint8Array(32); // all-zero — definitely not the KAT plaintext
    const r = await verifyTimestamp(token, wrong);
    expect(r.present).toBe(true);
    expect(r.valid).toBe(false);
    expect(r.badge).toBe('silver');
    expect(r.reason).toBe('imprint_mismatch');
  });
});

describe('verifyTimestamp — F2 AIA self-heal (2026-08-06)', () => {
  afterEach(() => {
    mockValidateTsaCertChain.mockClear();
    mockFetchIssuerCertViaAia.mockClear();
    mockIsProxied.mockClear();
  });

  it.runIf(HAS_KAT)(
    'no aiaFallback opt → chain_invalid is returned as-is, AIA is never attempted (old behavior, offline by default)',
    async () => {
      const token = loadKatToken();
      const meta = loadKatMeta();
      const signerSig = new TextEncoder().encode(meta.plaintext);
      mockValidateTsaCertChain.mockResolvedValueOnce({ ok: false, reason: 'chain_invalid' });
      const r = await verifyTimestamp(token, signerSig);
      expect(r.badge).toBe('silver');
      expect(r.reason).toBe('chain_invalid');
      expect(mockFetchIssuerCertViaAia).not.toHaveBeenCalled();
    },
  );

  it.runIf(HAS_KAT)(
    'aiaFallback opted in + local chain fails + AIA resolves a valid issuer → retries and reaches gold',
    async () => {
      const token = loadKatToken();
      const meta = loadKatMeta();
      const signerSig = new TextEncoder().encode(meta.plaintext);
      mockValidateTsaCertChain
        .mockResolvedValueOnce({ ok: false, reason: 'chain_invalid' })
        .mockResolvedValueOnce({ ok: true });
      // The exact cert bytes AIA "resolves" don't matter for this test — the
      // 2nd validateTsaCertChain call is mocked to succeed regardless, since
      // this test's job is to prove the ORCHESTRATION (mock the trust
      // decision itself; @firma-ec/tsa-trust's own tests already prove the
      // real UANATACA chain resolves for real).
      const fakeRoot = readFileSync(
        resolve(__dirname, '../../tsa-trust/tests/__fixtures__/uanataca-tsu01-leaf.der'),
      );
      mockFetchIssuerCertViaAia.mockResolvedValueOnce({
        ok: true,
        certDer: new Uint8Array(fakeRoot),
      });

      const r = await verifyTimestamp(token, signerSig, undefined, {});
      expect(mockFetchIssuerCertViaAia).toHaveBeenCalledOnce();
      expect(mockValidateTsaCertChain).toHaveBeenCalledTimes(2);
      expect(r.badge).toBe('gold');
      expect(r.valid).toBe(true);
    },
  );

  it.runIf(HAS_KAT)(
    'aiaFallback opted in + AIA itself fails → stays chain_invalid, does not throw',
    async () => {
      const token = loadKatToken();
      const meta = loadKatMeta();
      const signerSig = new TextEncoder().encode(meta.plaintext);
      mockValidateTsaCertChain.mockResolvedValueOnce({ ok: false, reason: 'chain_invalid' });
      mockFetchIssuerCertViaAia.mockResolvedValueOnce({ ok: false, reason: 'no_aia' });

      const r = await verifyTimestamp(token, signerSig, undefined, {});
      expect(mockValidateTsaCertChain).toHaveBeenCalledOnce();
      expect(r.badge).toBe('silver');
      expect(r.reason).toBe('chain_invalid');
    },
  );

  it.runIf(HAS_KAT)(
    'AIA resolves a cert, but the retried chain STILL fails → stays silver/chain_invalid (AIA gave us something, just not the missing link)',
    async () => {
      const token = loadKatToken();
      const meta = loadKatMeta();
      const signerSig = new TextEncoder().encode(meta.plaintext);
      mockValidateTsaCertChain
        .mockResolvedValueOnce({ ok: false, reason: 'chain_invalid' })
        .mockResolvedValueOnce({ ok: false, reason: 'chain_invalid' });
      const fakeCert = readFileSync(
        resolve(__dirname, '../../tsa-trust/tests/__fixtures__/uanataca-tsu01-leaf.der'),
      );
      mockFetchIssuerCertViaAia.mockResolvedValueOnce({
        ok: true,
        certDer: new Uint8Array(fakeCert),
      });

      const r = await verifyTimestamp(token, signerSig, undefined, {});
      expect(mockValidateTsaCertChain).toHaveBeenCalledTimes(2);
      expect(r.badge).toBe('silver');
      expect(r.reason).toBe('chain_invalid');
    },
  );

  it.runIf(HAS_KAT)(
    'reason=expired is NEVER retried via AIA (an AIA fetch cannot un-expire a cert)',
    async () => {
      const token = loadKatToken();
      const meta = loadKatMeta();
      const signerSig = new TextEncoder().encode(meta.plaintext);
      mockValidateTsaCertChain.mockResolvedValueOnce({ ok: false, reason: 'expired' });

      const r = await verifyTimestamp(token, signerSig, undefined, {});
      expect(mockFetchIssuerCertViaAia).not.toHaveBeenCalled();
      expect(r.reason).toBe('expired');
    },
  );
});
