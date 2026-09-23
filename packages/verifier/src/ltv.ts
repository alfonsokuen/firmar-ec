/**
 * verifyLtv — F7 T22.
 *
 * Inspects a parsed CMS SignerInfo + the DSS dict extracted from the PDF and
 * reports the highest LTV profile achieved (B-B / B-T / B-LT / B-LTA) plus
 * retrospective revocation status as embedded in the DSS.
 *
 * **Critical invariant** (spec §6.4 — LT-as-warning): LTV failure NEVER
 * invalidates the outer signature. Bad / corrupt / missing LTV data
 * downgrades the profile and accumulates warnings, but `result.signature.valid`
 * is decided by the F6 (timestamp) + path-validation paths.
 *
 * Browser-compatible. Uses `@firma-ec/ltv-validation` parsers and
 * `@firma-ec/dss-pdf` for document-timestamp discovery / verification.
 */

import { toHex } from '@firma-ec/crypto-core';
import { findDocumentTimestamps } from '@firma-ec/dss-pdf';
import {
  type ParsedCert as LtvParsedCert,
  OcspParseError,
  type ParsedOcspResponse,
  isCertRevoked,
  normalizeSerialHex,
  parseOcspResponse,
} from '@firma-ec/ltv-validation';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import type { Certificate } from 'pkijs';
import type { DssData } from './dss';
import type { TimestampSummary } from './result';
import { type TimestampVerification, verifyTimestamp } from './timestamp';

export type LtvProfile = 'B-B' | 'B-T' | 'B-LT' | 'B-LTA';

export interface DocumentTimestampSummary {
  /** Same shape as TimestampSummary for parity with F6. */
  present: boolean;
  valid: boolean;
  badge: 'gold' | 'silver' | 'none';
  signingTime?: string;
  tsaIssuer?: string;
  reason?: string;
}

export interface LtvSummary {
  profile: LtvProfile;
  dssPresent: boolean;
  embeddedOcspCount: number;
  embeddedCrlCount: number;
  /** True iff at least one cert in the chain had a retrospective `good`-or-equivalent status from embedded material. */
  retrospectiveValid: boolean;
  /**
   * Authenticated embedded evidence that the SIGNER cert (chain[0]) is revoked:
   * an OCSP response whose signature and CertID verified, or a CRL signed by
   * the signer's issuer. `revokedAt` is absent when the evidence gives no date.
   * The caller decides the verdict against the signature's proven time.
   */
  signerRevocation?: { revokedAt?: Date };
  /** Document timestamp (B-LTA). Absent when no /Sig /ETSI.RFC3161 found. */
  documentTimestamp?: DocumentTimestampSummary;
  /** Free-form diagnostic strings — never block outer signature. */
  errors: string[];
}

function toAb(u: Uint8Array): ArrayBuffer {
  return u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;
}

function getCN(cert: Certificate): string | null {
  for (const tv of cert.subject.typesAndValues as unknown as {
    type: string;
    value: { valueBlock: { value?: string } };
  }[]) {
    if (tv.type === '2.5.4.3') {
      const v = tv.value?.valueBlock?.value;
      if (typeof v === 'string') return v;
    }
  }
  return null;
}

/**
 * Merge a newly found revocation into what is already known, keeping the one
 * that decides a verdict: the earliest date, and an undated revocation over
 * any dated one (fail closed).
 */
function earlierRevocation(
  known: { revokedAt?: Date } | undefined,
  revokedAt: Date | undefined,
): { revokedAt?: Date } {
  if (known && known.revokedAt === undefined) return known;
  if (revokedAt === undefined) return {};
  if (known?.revokedAt && known.revokedAt <= revokedAt) return known;
  return { revokedAt };
}

/** The issuer's public-key hash under each CertID algorithm (RFC 6960 §4.1.1). */
export async function issuerKeyHashByAlgo(
  issuer: Certificate,
): Promise<{ sha1: string; sha256: string }> {
  const spki = toAb(
    new Uint8Array(issuer.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView),
  );
  const [sha1, sha256] = await Promise.all([
    crypto.subtle.digest('SHA-1', spki),
    crypto.subtle.digest('SHA-256', spki),
  ]);
  return { sha1: bufToHexLocal(sha1), sha256: bufToHexLocal(sha256) };
}

/** True when `crl` names `issuer` as its issuer and carries a signature `issuer` made. */
async function crlIssuedBy(
  crl: pkijs.CertificateRevocationList,
  issuer: Certificate,
): Promise<boolean> {
  if (!crl.issuer.isEqual(issuer.subject)) return false;
  try {
    return await crl.verify({ issuerCertificate: issuer });
  } catch {
    return false;
  }
}

export function toLtvParsedCert(cert: Certificate): LtvParsedCert {
  const der = new Uint8Array(cert.toSchema().toBER(false));
  return {
    subjectCN: getCN(cert),
    issuerCN: (() => {
      for (const tv of cert.issuer.typesAndValues as unknown as {
        type: string;
        value: { valueBlock: { value?: string } };
      }[]) {
        if (tv.type === '2.5.4.3') {
          const v = tv.value?.valueBlock?.value;
          if (typeof v === 'string') return v;
        }
      }
      return null;
    })(),
    der,
    notBefore: cert.notBefore.value as Date,
    notAfter: cert.notAfter.value as Date,
  };
}

/**
 * Compute the VRI lookup key per ETSI — uppercase hex of SHA-1 over the
 * signature /Contents bytes.
 */
async function vriKeyFor(signatureContents: Uint8Array): Promise<string> {
  // ETSI EN 319 142-1 §5.4 mandates SHA-1 for the VRI key (legacy hashing
  // chosen for compatibility with Acrobat). crypto-core caps at SHA-256; use
  // WebCrypto directly.
  const ab = signatureContents.buffer.slice(
    signatureContents.byteOffset,
    signatureContents.byteOffset + signatureContents.byteLength,
  ) as ArrayBuffer;
  const h = new Uint8Array(await crypto.subtle.digest('SHA-1', ab));
  return toHex(h).toUpperCase();
}

/**
 * Try to parse a CRL DER. Returns null if malformed.
 */
function tryParseCrl(der: Uint8Array): pkijs.CertificateRevocationList | null {
  try {
    const asn = asn1js.fromBER(toAb(der));
    if (asn.offset === -1) return null;
    return new pkijs.CertificateRevocationList({ schema: asn.result });
  } catch {
    return null;
  }
}

function bufToHexLocal(buf: ArrayBuffer | Uint8Array): string {
  const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let out = '';
  for (let i = 0; i < u.length; i++) out += (u[i] ?? 0).toString(16).padStart(2, '0');
  return out;
}

export function serialHexOf(cert: Certificate): string {
  const serialBuf = (cert.serialNumber.valueBlock as { valueHex: ArrayBuffer }).valueHex;
  return bufToHexLocal(serialBuf);
}

/**
 * Pull `responderCert` (or null) suitable for parseOcspResponse. We pass the
 * cert under question's issuer — the LTV layer expects issuer for chain
 * resolution — plus `subject`'s serial as the expected CertID (RFC 6960
 * §4.2.1 anti-replay match; see `ocsp/response.ts`'s module doc). A response
 * that turns out to answer a DIFFERENT cert throws `OcspParseError` and is
 * treated the same as any other unusable entry: skipped, never `null`-crash.
 */
async function tryParseOcsp(
  der: Uint8Array,
  issuerParsed: LtvParsedCert,
  subject: Certificate,
  issuer: Certificate,
): Promise<ParsedOcspResponse | null> {
  try {
    return await parseOcspResponse(der, issuerParsed, {
      serialHex: serialHexOf(subject),
      issuerKeyHashByAlgo: await issuerKeyHashByAlgo(issuer),
    });
  } catch (e) {
    if (e instanceof OcspParseError) return null;
    return null;
  }
}

/**
 * Decide if an OCSP response matches a particular subject cert.
 *
 * Match is issuerKeyHash + serial, both normalized — a prior version stripped
 * the subject's leading zero pad byte but compared it against the response's
 * `serialHex` UNNORMALIZED, so any cert whose DER serial carries the 0x00
 * high-bit pad byte never matched and its embedded revocation evidence
 * (including an explicit `revoked`) was silently ignored. `issuerKeyHash` is
 * hashed with whatever algorithm the response itself reports
 * (`certIdHashAlgo`) — an unrecognized algorithm can't be corroborated, so it
 * is treated as a non-match rather than skipping the check.
 */
export async function ocspMatchesCert(
  parsed: ParsedOcspResponse,
  subject: Certificate,
  issuer: Certificate,
): Promise<boolean> {
  if (normalizeSerialHex(parsed.serialHex) !== normalizeSerialHex(serialHexOf(subject)))
    return false;
  if (parsed.certIdHashAlgo === 'other') return false;
  const digestName = parsed.certIdHashAlgo === 'sha1' ? 'SHA-1' : 'SHA-256';
  const spki = new Uint8Array(issuer.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView);
  const hash = new Uint8Array(await crypto.subtle.digest(digestName, toAb(spki)));
  return parsed.issuerKeyHashHex.toLowerCase() === bufToHexLocal(hash).toLowerCase();
}

export interface VerifyLtvOpts {
  /** When the document timestamp is present, the verifier can resolve `documentTimestamp` against TSL roots. */
  trustRoots?: unknown;
}

/**
 * Inspect DSS material against the signing chain and produce an LtvSummary.
 *
 * @param chain  signer cert at index 0, followed by intermediates (issuer
 *               first, then roots). May be empty when path validation failed.
 * @param dss    parsed DSS dict (or undefined when the PDF has no /DSS).
 * @param signatureContents raw signature /Contents bytes from the PDF (for VRI key).
 * @param pdfBytes full PDF — only used to locate document timestamps (B-LTA).
 */
interface DocTsResult {
  documentTimestamp?: DocumentTimestampSummary;
  archiveAchieved: boolean;
  error?: string;
}

// v0.7.41 — the B-LTA document-timestamp scan + verification is identical for
// every signature in the same PDF (it inspects the document, not the signer),
// yet `verifyLtv` is called once per signature. On a multi-signature PDF that
// meant `findDocumentTimestamps` + the archive `verifyTimestamp` (which hashes
// the whole PDF) ran N times — heavy redundant work that, combined with
// sequential per-signature processing, made a 6-signature B-LTA crawl. Cache it
// by the pdfBytes reference (the SAME Uint8Array is handed to every signature
// within a single verifyAllSignatures run), so it executes exactly once.
const docTsCache = new WeakMap<Uint8Array, Promise<DocTsResult>>();

async function computeDocumentTimestamp(pdfBytes: Uint8Array): Promise<DocTsResult> {
  try {
    const stamps = findDocumentTimestamps(pdfBytes);
    if (stamps.length === 0) return { archiveAchieved: false };
    // Verify the LAST one (most-recent in document order — the archive seal).
    const stamp = stamps[stamps.length - 1]!;
    const ver: TimestampVerification = await verifyTimestamp(stamp.tokenDer, {
      imprintSource: stamp.coveredBytes,
    });
    const documentTimestamp: DocumentTimestampSummary = {
      present: ver.present,
      valid: ver.valid,
      badge: ver.badge,
    };
    if (ver.signingTime) documentTimestamp.signingTime = ver.signingTime.toISOString();
    if (ver.tsaIssuer) documentTimestamp.tsaIssuer = ver.tsaIssuer;
    if (ver.reason) documentTimestamp.reason = ver.reason;
    return { documentTimestamp, archiveAchieved: ver.valid };
  } catch (e) {
    return {
      archiveAchieved: false,
      error: `document_timestamp_scan_failed: ${(e as Error).message}`,
    };
  }
}

export async function verifyLtv(
  chain: Certificate[],
  dss: DssData | undefined,
  signatureContents: Uint8Array,
  pdfBytes: Uint8Array,
  _opts: VerifyLtvOpts = {},
): Promise<LtvSummary> {
  const errors: string[] = [];

  // --- B-LTA detection (document timestamps), computed once per PDF ---------
  let docTsPromise = docTsCache.get(pdfBytes);
  if (!docTsPromise) {
    docTsPromise = computeDocumentTimestamp(pdfBytes);
    docTsCache.set(pdfBytes, docTsPromise);
  }
  const { documentTimestamp, archiveAchieved, error: docTsError } = await docTsPromise;
  if (docTsError) errors.push(docTsError);

  // --- B-LT inspection -------------------------------------------------
  if (!dss) {
    // No DSS — profile is whatever the timestamp layer said (decided by
    // the caller). We return profile B-B as the LTV default; the caller's
    // state machine upgrades to B-T based on TimestampSummary.
    const out: LtvSummary = {
      profile: 'B-B',
      dssPresent: false,
      embeddedOcspCount: 0,
      embeddedCrlCount: 0,
      retrospectiveValid: false,
      errors,
    };
    if (documentTimestamp) out.documentTimestamp = documentTimestamp;
    return out;
  }

  const embeddedOcspCount = dss.ocsps.length;
  const embeddedCrlCount = dss.crls.length;

  // VRI-keyed lookup (per ETSI): the entry keyed by SHA-1(signatureContents)
  // contains the indices of OCSP/CRL streams that apply to THIS signature.
  let vriEntry: (typeof dss.vri)[string] | undefined;
  try {
    const key = await vriKeyFor(signatureContents);
    vriEntry = dss.vri[key];
  } catch (e) {
    errors.push(`vri_key_failed: ${(e as Error).message}`);
  }

  // Build the set of OCSP/CRL indices to consult. Prefer VRI-scoped material;
  // fall back to all DSS material when VRI is absent / empty.
  const ocspIdx = vriEntry?.ocspIndices?.length ? vriEntry.ocspIndices : dss.ocsps.map((_, i) => i);
  const crlIdx = vriEntry?.crlIndices?.length ? vriEntry.crlIndices : dss.crls.map((_, i) => i);

  // Retrospective check: for each cert in the chain (excluding root), see if
  // we have an OCSP `good` or a CRL that *doesn't* list this cert. If at
  // least one cert is positively cleared, we mark retrospectiveValid=true;
  // any explicit revoked DOES set retrospectiveValid=false (and downgrades
  // the badge — but does not invalidate the outer sig).
  let retrospectiveValid = false;
  let revokedFound = false;

  // Perf (v0.7.35): parse each cert / CRL / OCSP at most ONCE per signature.
  // The original loop re-serialised every issuer cert (`cert.toSchema().toBER`)
  // and re-parsed the same (often multi-MB ARCOTEL) CRL once per chain link,
  // i.e. O(chain × DSS-entries) heavy ASN.1 work. Fast on desktop V8 but >30s
  // on a mobile CPU for a 6-signature B-LTA PDF (the `verify:#5 ltv` hang
  // reported 2026-05-20). Memoising collapses it to O(chain + DSS-entries).
  const parsedCertCache = new Map<Certificate, LtvParsedCert>();
  const parseCert = (c: Certificate): LtvParsedCert => {
    let p = parsedCertCache.get(c);
    if (!p) {
      p = toLtvParsedCert(c);
      parsedCertCache.set(c, p);
    }
    return p;
  };
  const crlCache = new Map<number, pkijs.CertificateRevocationList | null>();
  const parseCrlCached = (idx: number, der: Uint8Array): pkijs.CertificateRevocationList | null => {
    if (crlCache.has(idx)) return crlCache.get(idx) ?? null;
    const crl = tryParseCrl(der);
    crlCache.set(idx, crl);
    return crl;
  };
  // OCSP parse depends on the issuer, so key by (ocsp index | chain link).
  const ocspCache = new Map<string, ParsedOcspResponse | null>();

  // Hard bounds (v0.7.37) so LTV — which is purely informational and NEVER
  // invalidates the outer signature (spec §6.4) — cannot hang the verification
  // on a mobile CPU. The `verify:#5 ltv` 30s hang persisted after memoisation
  // (0.7.36) because a SINGLE ARCOTEL CRL can be megabytes; one synchronous
  // pkijs parse of it alone exceeds 30s on the device. We:
  //   1. Skip any CRL larger than MAX_CRL_BYTES (a full parse would block the
  //      worker thread past the watchdog). The profile (B-LT/B-LTA) is still
  //      derived from DSS *presence*, so the only thing lost is the
  //      retrospective revoked/good detail — surfaced as a warning.
  //   2. Bail out of the retrospective loop once LTV_BUDGET_MS elapses.
  // Either way the signature still reports its real validity; LTV degrades to a
  // note rather than freezing the UI.
  // v0.7.40 — the `verify:#5 ltv` hang survived a Promise.race(12s) deadline
  // (0.7.39). That is conclusive proof the worker thread is blocked
  // SYNCHRONOUSLY: a setTimeout deadline cannot fire while synchronous code
  // holds the single thread. The only large variable-size synchronous parse in
  // this path is pkijs `new CertificateRevocationList()`, which expands EVERY
  // revoked entry into an object — an ARCOTEL CRL with hundreds of thousands of
  // entries takes >30s on a mobile CPU. So the cap must be small enough that a
  // parse always finishes well under the watchdog. 100 KB parses in well under
  // a second; larger CRLs are skipped (LTV is informational — profile is still
  // derived from DSS presence). OCSP responses are normally ~1-2 KB; cap them
  // too as defense in depth against a pathological large response.
  const MAX_CRL_BYTES = 100_000;
  const MAX_OCSP_BYTES = 100_000;
  const LTV_BUDGET_MS = 8_000;
  const ltvStart = Date.now();
  let budgetTripped = false;

  let signerRevocation: LtvSummary['signerRevocation'];

  // We need pairs (subject, issuer) to verify OCSP signatures correctly.
  for (let i = 0; i < chain.length - 1; i++) {
    if (Date.now() - ltvStart > LTV_BUDGET_MS) {
      budgetTripped = true;
      break;
    }
    const subject = chain[i]!;
    const issuer = chain[i + 1]!;
    let linkRevoked = false;
    const issuerParsed = parseCert(issuer);

    // OCSP first (preferred).
    for (const idx of ocspIdx) {
      if (Date.now() - ltvStart > LTV_BUDGET_MS) {
        budgetTripped = true;
        break;
      }
      const ocspDer = dss.ocsps[idx];
      if (!ocspDer) continue;
      if (ocspDer.byteLength > MAX_OCSP_BYTES) {
        if (!errors.includes('ocsp_too_large_skipped')) {
          errors.push(`ocsp_too_large_skipped: ${ocspDer.byteLength} bytes`);
        }
        continue;
      }
      const ocspKey = `${idx}|${i + 1}`;
      let parsed: ParsedOcspResponse | null;
      if (ocspCache.has(ocspKey)) {
        parsed = ocspCache.get(ocspKey) ?? null;
      } else {
        parsed = await tryParseOcsp(ocspDer, issuerParsed, subject, issuer);
        ocspCache.set(ocspKey, parsed);
      }
      if (!parsed) continue;
      // Embedded DSS evidence is attacker-supplied: a revoked signer can staple
      // a forged `good` response whose CertID matches. Reading certStatus before
      // the signature is checked buys nothing — see response.ts.
      if (!parsed.signatureValid) continue;
      if (!(await ocspMatchesCert(parsed, subject, issuer))) continue;
      // Nothing ends the search early: the DSS order is chosen by whoever wrote
      // the PDF, and a later entry (or a CRL below) may prove an EARLIER
      // revocation. The earliest authenticated revocation is what counts.
      if (parsed.certStatus === 'revoked') {
        if (!linkRevoked) errors.push(`cert_revoked: ${getCN(subject) ?? 'unknown'}`);
        revokedFound = true;
        linkRevoked = true;
        if (i === 0) signerRevocation = earlierRevocation(signerRevocation, parsed.revokedAt);
      } else if (parsed.certStatus === 'good') {
        retrospectiveValid = true;
      }
    }

    // CRLs too: an OCSP `good` must not hide a CRL that lists the cert.
    for (const idx of crlIdx) {
      if (Date.now() - ltvStart > LTV_BUDGET_MS) {
        budgetTripped = true;
        break;
      }
      const crlDer = dss.crls[idx];
      if (!crlDer) continue;
      // Skip CRLs too large to parse synchronously without blocking past the
      // watchdog. The profile is unaffected (derived from DSS presence).
      if (crlDer.byteLength > MAX_CRL_BYTES) {
        if (!errors.includes('crl_too_large_skipped')) {
          errors.push(
            `crl_too_large_skipped: ${crlDer.byteLength} bytes (revocación a largo plazo no verificada en este dispositivo)`,
          );
        }
        continue;
      }
      const crl = parseCrlCached(idx, crlDer);
      if (!crl) continue;
      // DSS material can be appended after signing by anyone: only a CRL the
      // subject's issuer actually signed says anything about the subject.
      if (!(await crlIssuedBy(crl, issuer))) continue;
      const status = isCertRevoked(parseCert(subject), crl);
      if (status.revoked) {
        if (!linkRevoked) errors.push(`cert_revoked_crl: ${getCN(subject) ?? 'unknown'}`);
        revokedFound = true;
        linkRevoked = true;
        if (i === 0) signerRevocation = earlierRevocation(signerRevocation, status.revokedAt);
      } else {
        retrospectiveValid = true;
      }
    }
  }

  // An interrupted scan may have stopped before the entry that proves a
  // revocation: it can report what it found, never that revocation was
  // checked and came out good.
  if (budgetTripped) retrospectiveValid = false;
  if (budgetTripped && !errors.includes('crl_too_large_skipped')) {
    errors.push(
      'ltv_budget_exceeded: revocación a largo plazo no verificada por completo en este dispositivo',
    );
  }

  // Profile decision: B-LTA when document timestamp valid + DSS present;
  // else B-LT when DSS has any revocation material; else B-T (decided by
  // caller). The caller's state machine bumps profile to max(verifier-side
  // profile, this profile).
  let profile: LtvProfile;
  if (archiveAchieved && (embeddedOcspCount > 0 || embeddedCrlCount > 0)) {
    profile = 'B-LTA';
  } else if (embeddedOcspCount > 0 || embeddedCrlCount > 0) {
    profile = 'B-LT';
  } else {
    // DSS present but empty — degenerate. Treat as B-T.
    profile = 'B-T';
    errors.push('dss_present_but_empty');
  }

  if (revokedFound) {
    // We still report the profile (B-LT / B-LTA) because the DSS material
    // is structurally valid; the consumer surfaces the revocation as a
    // warning. Outer signature stays valid (LTV is informational).
  }

  const result: LtvSummary = {
    profile,
    dssPresent: true,
    embeddedOcspCount,
    embeddedCrlCount,
    retrospectiveValid: retrospectiveValid && !revokedFound,
    errors,
  };
  if (signerRevocation) result.signerRevocation = signerRevocation;
  if (documentTimestamp) result.documentTimestamp = documentTimestamp;
  return result;
}

/** Re-exported for index.ts convenience. */
export type { TimestampSummary };
