import {
  digest,
  ecCertIdentity,
  isWithinValidity,
  issuerInfo,
  resolveIssuerCert,
  subjectInfo,
  toHex,
} from '@firma-ec/crypto-core';
import { type TrustIntermediate, getIntermediates, getTrustRoots } from '@firma-ec/tsl-ec';
import { fromBER } from 'asn1js';
import { Certificate } from 'pkijs';
import { parseCms } from './cms';
import { extractDss } from './dss';
import { VerificationError } from './errors';
import { buildCoveredBytes, checkDocumentIntegrity, verifySignatureValue } from './integrity';
import { verifyLtv } from './ltv';
import { checkOcsp } from './ocsp';
import { validatePath } from './pathValidation';
import { type SignedRange, findAllSignatures, findSignature } from './pdf';
import type { Status, VerificationResult } from './result';
import { verifyTimestamp } from './timestamp';

export type {
  VerificationResult,
  Status,
  SignerSummary,
  SignatureMeta,
  OcspStatus,
  IntegrityCheck,
  VerificationWarning,
  TimestampSummary,
  LtvSummary,
} from './result';
export type { TimestampVerification, TimestampBadge, TimestampReason } from './timestamp';
export type { LtvProfile, DocumentTimestampSummary } from './ltv';
export { verifyTimestamp } from './timestamp';
export { extractDss } from './dss';
export { verifyLtv } from './ltv';
export { VerificationError } from './errors';
export { checkCertificate } from './certCheck';
export type { CertCheckResult, CertCheckOptions } from './certCheck';

// Bump on each release (kept hardcoded — JSON imports require resolveJsonModule
// + downstream tsconfig coupling we'd rather avoid in this package).
export const ENGINE_VERSION = '0.10.0';

/**
 * Dedupe a certificate list by DER fingerprint. Used to merge intermediates
 * harvested from multiple signatures in the same PDF before chain validation.
 */
function mergeCertsDedup(certs: import('pkijs').Certificate[]): import('pkijs').Certificate[] {
  const seen = new Set<string>();
  const out: import('pkijs').Certificate[] = [];
  for (const c of certs) {
    try {
      const der = new Uint8Array(c.toSchema().toBER(false));
      let key = '';
      for (let i = 0; i < der.length; i += 1) key += der[i]!.toString(16).padStart(2, '0');
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(c);
    } catch {
      // Cert that can't be DER-encoded shouldn't be in the chain anyway — skip.
    }
  }
  return out;
}

export interface VerifyOptions {
  /** Whether to query OCSP responders. Default true; set false for offline mode. */
  fetchOcsp?: boolean | undefined;
  /** Override the TSL roots; default fetched from @firma-ec/tsl-ec. */
  trustRoots?: Awaited<ReturnType<typeof getTrustRoots>> | undefined;
  /**
   * Override the bundled subordinate-CA intermediates used to complete a chain
   * when the PDF (and its sibling signatures) omit them. Default fetched from
   * @firma-ec/tsl-ec. These are NOT trust anchors — they only bridge a leaf to
   * an already-trusted root, so supplying them can never make an untrusted cert
   * trusted. Pass `[]` to disable bundled-intermediate completion.
   */
  trustIntermediates?: TrustIntermediate[] | undefined;
  /**
   * F2 (2026-08-06) — whether to try the AIA `caIssuers` self-heal fallback
   * when a signature's embedded RFC 3161 timestamp's TSA cert doesn't chain
   * to a trusted @firma-ec/tsa-trust root (real UANATACA case: the token
   * ships leaf-only). Default true, same posture as `fetchOcsp` — a failure
   * here only keeps the existing non-blocking `chain_invalid` warning, it
   * never fails the outer signature. Set false for a fully offline verify
   * (mirrors `fetchOcsp: false`).
   */
  fetchTsaAia?: boolean | undefined;
}

/** Parse a PEM certificate string into a pkijs Certificate. */
function pemToCert(pem: string): Certificate {
  const b64 = pem.replace(/-----BEGIN [A-Z ]+-----|-----END [A-Z ]+-----|\s/g, '');
  const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const asn = fromBER(
    der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength) as ArrayBuffer,
  );
  if (asn.offset === -1) throw new Error('PEM ASN.1 decode failed');
  return new Certificate({ schema: asn.result });
}

/** Cache of the default bundled-intermediate pkijs Certificates (parsed once). */
let defaultBundledInterCache: Certificate[] | null = null;

/**
 * Resolve the bundled subordinate-CA intermediate certificates as pkijs
 * Certificates. Uses {@link VerifyOptions.trustIntermediates} when provided
 * (tests / private CAs), otherwise the @firma-ec/tsl-ec bundle (cached).
 */
async function resolveBundledIntermediates(opts: VerifyOptions): Promise<Certificate[]> {
  const override = opts.trustIntermediates;
  if (override !== undefined) {
    const out: Certificate[] = [];
    for (const it of override) {
      try {
        out.push(pemToCert(it.pemContent));
      } catch {
        /* skip unparseable */
      }
    }
    return out;
  }
  if (defaultBundledInterCache) return defaultBundledInterCache;
  const list = await getIntermediates();
  const out: Certificate[] = [];
  for (const it of list) {
    try {
      out.push(pemToCert(it.pemContent));
    } catch {
      /* skip unparseable */
    }
  }
  defaultBundledInterCache = out;
  return out;
}

/**
 * From a pool of bundled subordinate-CA certs, return ONLY the ones that bridge
 * `signerCert` toward its root — i.e. walk leaf → issuer → … and pull a bundled
 * cert whenever the next issuer is missing from `present`. This is deliberately
 * selective: dumping the whole bundle into pkijs's `certs[]` pollutes the pool
 * with orphan CAs (whose own issuer isn't trusted), which makes pkijs's chain
 * engine reject otherwise-valid chains. Adding only the needed links avoids that
 * and can never grant trust (pkijs still must terminate at a trusted root).
 */
async function selectBridgingIntermediates(
  signerCert: Certificate,
  present: Certificate[],
  bundle: Certificate[],
): Promise<Certificate[]> {
  const pool = [...present];
  const added: Certificate[] = [];
  let cur: Certificate | undefined = signerCert;
  for (let depth = 0; depth < 8 && cur !== undefined; depth++) {
    if (cur.subject.isEqual(cur.issuer)) break; // self-signed → done
    // 2026-08-23 fix: mismo criterio que el bundle de abajo — los certs
    // presentes en el CMS pueden incluir dos homónimas de una renovación; el
    // `.find()` plano seguía la primera. resolveIssuerCert elige la emisora
    // real; si ninguna homónima del pool resuelve, se puentea desde el bundle.
    const inPool = await resolveIssuerCert(cur, pool);
    if (inPool) {
      if (inPool === cur) break;
      cur = inPool;
      continue;
    }
    // 2026-08-05 HIGH fix: bundle can hold several intermediates that share
    // the same subject DN (e.g. BCE's 2011/2019 subCA renewal). A plain
    // `.find()` would pick whichever is declared first regardless of whether
    // it actually issued `cur` — see resolveIssuerCert's doc in crypto-core.
    const match = await resolveIssuerCert(cur, bundle);
    if (!match) break;
    added.push(match);
    pool.push(match);
    cur = match;
  }
  return added;
}

/**
 * Verify a single PAdES signature against the given PDF bytes. Internal helper
 * used by both `verifyPdf` (first/only signature, back-compat) and
 * `verifyAllSignatures` (enumerates every signature for multi-firma PDFs).
 *
 * Accepts `sig` already located by `findSignature` / `findAllSignatures` so
 * the caller can iterate without re-parsing the PDF once per signature.
 */
async function verifyOneSignature(
  pdfBytes: Uint8Array,
  sig: SignedRange,
  opts: VerifyOptions,
  roots: Awaited<ReturnType<typeof getTrustRoots>>,
  verifiedAt: string,
  sharedIntermediates: import('pkijs').Certificate[] = [],
  /** True iff this is the latest signature in the PDF. Sigs before the latest
   * always have "bytes after them" because subsequent sigs were appended via
   * legitimate PAdES incremental update — those should NOT raise
   * `incremental_updates`. */
  isLatestSignature = true,
  /** v0.7.29 — true when the bytes appended after this signature correspond
   * to a PAdES B-LTA document timestamp (legitimate /SubFilter /ETSI.RFC3161
   * wrap, not tampering). When set, suppresses the `incremental_updates`
   * warning even if `sig.hasIncrementalUpdates` is true. */
  appendedBytesAreDocTimeStamp = false,
  /** See {@link verifyAllSignatures}. Local to the worker — never crosses the
   * postMessage boundary. */
  onProgress?: (stage: string) => void,
  /** Signature index for progress labels in multi-firma PDFs (undefined for
   * single-sig so labels stay terse). */
  sigIndex?: number,
): Promise<VerificationResult> {
  const warnings: VerificationResult['warnings'] = [];
  // Per-phase progress beacon. Each call resets the bus watchdog (so a slow
  // mobile CPU is not killed mid-verification) and localizes a true hang.
  const tag = sigIndex === undefined ? '' : `#${sigIndex} `;
  const phase = (name: string): void => onProgress?.(`verify:${tag}${name}`);
  try {
    phase('cms');
    const cms = await parseCms(sig.contents);

    // Integrity: document hash + signature value
    phase('integrity');
    let docCheck: { matches: boolean; computed: Uint8Array };
    let sigValid: boolean;
    // Set when the document digest relies on SHA-1 (weak) — drives a warning.
    let weakSha1 = false;

    if (sig.subFilter === 'adbe.pkcs7.sha1') {
      // Legacy Adobe `adbe.pkcs7.sha1`: the CMS eContent carries SHA-1(byteRange)
      // (the document hash), and the signature is computed over that eContent
      // (or over signed attrs whose message-digest equals hash(eContent)). The
      // document integrity therefore always rests on SHA-1 → weak. Used by BCE
      // and Security Data Ecuadorian gov documents. Accepted for reading, but
      // surfaced as a weak-hash warning (never a bare 'valid').
      const covered = buildCoveredBytes(pdfBytes, sig.byteRange);
      const sha1Covered = new Uint8Array(
        await crypto.subtle.digest(
          'SHA-1',
          covered.buffer.slice(
            covered.byteOffset,
            covered.byteOffset + covered.byteLength,
          ) as ArrayBuffer,
        ),
      );
      const ec = cms.eContent;
      const docMatches =
        ec !== undefined &&
        ec.length === sha1Covered.length &&
        ec.every((v, i) => v === sha1Covered[i]);
      weakSha1 = true;
      // RFC 5652 §5.4: with signed attrs the signature is over them; without,
      // it is over the eContent directly.
      const signedData = cms.hasSignedAttrs ? cms.signedAttrsDer : (ec ?? new Uint8Array());
      sigValid = await verifySignatureValue(
        cms.signerCert,
        cms.signatureAlgoOid,
        cms.digestAlgoOid,
        signedData,
        cms.signatureValue,
        { allowSha1: true },
      );
      docCheck = { matches: docMatches, computed: sha1Covered };
    } else if (cms.hasSignedAttrs) {
      // PAdES-B-B: signature is over the signed attributes; the message-digest
      // attribute must equal hash(coveredBytes).
      docCheck = await checkDocumentIntegrity(
        pdfBytes,
        sig.byteRange,
        cms.digestAlgoOid,
        cms.signedMessageDigest ?? new Uint8Array(),
      );
      sigValid = await verifySignatureValue(
        cms.signerCert,
        cms.signatureAlgoOid,
        cms.digestAlgoOid,
        cms.signedAttrsDer,
        cms.signatureValue,
      );
    } else {
      // Bare CAdES-BES (no signed attributes, non-adbe): the signature is
      // computed directly over the eContent = the /ByteRange-covered bytes, so
      // integrity is established BY the signature verifying over that content.
      const covered = buildCoveredBytes(pdfBytes, sig.byteRange);
      weakSha1 = cms.digestAlgoOid === '1.3.14.3.2.26';
      sigValid = await verifySignatureValue(
        cms.signerCert,
        cms.signatureAlgoOid,
        cms.digestAlgoOid,
        covered,
        cms.signatureValue,
        { allowSha1: true },
      );
      docCheck = { matches: sigValid, computed: new Uint8Array() };
    }

    // F6 — RFC 3161 timestamp verification. Best-effort: never degrades the
    // outer signature validity (silver only adds a warning; spec §6.2).
    phase('tsa');
    const tsaResult = await verifyTimestamp(
      cms.timestampToken,
      cms.signatureValue,
      undefined,
      opts.fetchTsaAia !== false ? {} : undefined,
    );

    // F7 — DSS extraction + LTV summary. Best-effort: never degrades outer
    // signature validity (LT-as-warning; spec §6.4).
    const dssOutcome = extractDss(pdfBytes);
    if (dssOutcome.error) {
      warnings.push({ code: 'dss_malformed', message: dssOutcome.error });
    }

    // Path validation. Multi-sig PDFs (e.g. iCert-EC judicial documents) may
    // have one signer that didn't embed the chain in its CMS while a sibling
    // signature did. Merge cms.intermediates with sharedIntermediates harvested
    // from every other signature in the same PDF, deduped by DER fingerprint.
    // Bundled subordinate-CA intermediates (e.g. UANATACA CA2 2016) complete the
    // path when a leaf-only CMS omits its issuing intermediate and no sibling
    // signature carried it. They are not trust anchors — pkijs still requires
    // termination at a trusted self-signed root — so this can only ever help a
    // cert that already chains to an accredited ACE root, never grant trust.
    const bundlePool = await resolveBundledIntermediates(opts);
    const present = [cms.signerCert, ...cms.intermediates, ...sharedIntermediates];
    const bridging = await selectBridgingIntermediates(cms.signerCert, present, bundlePool);
    const mergedIntermediates = mergeCertsDedup([
      ...cms.intermediates,
      ...sharedIntermediates,
      ...bridging,
    ]);
    phase('chain');
    // Validate the chain at the time the signature is PROVEN to exist: the
    // time of a verified RFC 3161 timestamp, so a cert that was valid when the
    // document was timestamped keeps validating after it expires. Without one,
    // the CMS signing-time / PDF /M date are only the signer's word — trusting
    // them let an expired cert with a backdated date verify as fully `valid`
    // (2026-09-23). Then validate at the current time, and only if that fails
    // fall back to the declared time, reported as `signing_time_unproven`.
    const proofOfExistence =
      tsaResult.valid && tsaResult.signingTime ? tsaResult.signingTime : undefined;
    const declaredSigningTime = cms.signingTime ?? sig.signingTimeM;
    let path = await validatePath(
      cms.signerCert,
      mergedIntermediates,
      roots,
      proofOfExistence ?? new Date(),
    );
    // A timestamp only proves the signature existed AT THE LATEST at its
    // time, so a declared date before it is retried too (a timestamp added
    // after the cert expired): valid then, but still only on the signer's word.
    let signingTimeUnproven = false;
    if (
      !path.success &&
      declaredSigningTime &&
      (!proofOfExistence || declaredSigningTime.getTime() < proofOfExistence.getTime())
    ) {
      const atDeclared = await validatePath(
        cms.signerCert,
        mergedIntermediates,
        roots,
        declaredSigningTime,
      );
      if (atDeclared.success) {
        path = atDeclared;
        signingTimeUnproven = true;
      }
    }

    // Detect "trust chain inconclusive due to placeholder TSL" — this is NOT a
    // crypto failure, just a missing trust anchor. We must NOT degrade to
    // 'invalid' in this case: hash + signature are sound, but the trust list
    // hasn't published real ARCOTEL roots yet (F2 / pre-v0.2.0 state). The PWA
    // shows a DEMO banner when this warning code appears.
    //
    // Heuristic: if all TSL roots are placeholders, no real chain can succeed
    // even for a perfectly signed ECI/Security Data PDF. Treat that as
    // 'warning' with code TRUST_PLACEHOLDER (consumed by Verificar.svelte).
    //
    // 2026-09-23: the F6.7 "partial" softening (some roots placeholder →
    // every chain failure became 'warning') was removed. It could not tell a
    // missing placeholder root from a forged or unaccredited chain, so a
    // single placeholder in the TSL would have softened every rejection.
    //
    // 2026-05-14: ACEs flagged isDefunct (ARCOTEL-listed but no operational
    // public presence) are excluded from the active denominator so the banner
    // reflects only currently-issuing CAs.
    const activeRoots = roots.filter((r) => !r.isDefunct && !r.isParallelAnchor);
    const placeholderCount = activeRoots.filter((r) => r.isPlaceholder).length;
    const allRootsPlaceholder = activeRoots.length > 0 && placeholderCount === activeRoots.length;
    const trustInconclusive = !path.success && allRootsPlaceholder;

    // OCSP (optional). Per ETSI EN 319 142-1, revocation status at verification
    // time is only REQUIRED for B-LT / B-LTA profiles (which embed it in DSS).
    // For B-B / B-T the spec leaves revocation to the validation policy — and
    // FirmaEC desktop (the reference implementation in EC) does not fetch OCSP
    // online for B-B. We mirror that behaviour: only attempt online OCSP when
    // a TSA timestamp is present (signature is at least B-T). This eliminates
    // the noisy `ocsp_unavailable` warning on B-B PDFs caused by responders
    // without CORS — a transport failure is not evidence of revocation.
    //
    // v0.7.32 — Skip live OCSP entirely when the signature carries embedded
    // DSS revocation (B-LT / B-LTA). The DSS already contains the OCSP/CRL
    // material captured at signing time, which is exactly the revocation
    // evidence these profiles require — a live fetch is redundant. It is also
    // actively harmful: the `ocsp.firmar.ec` proxy is not always reachable,
    // and on mobile networks an unreachable host black-holes the connection
    // (no fast RST), so the fetch stalls instead of failing fast. That stall
    // hung the whole verification on Android Chrome (reported 2026-05-20).
    // Only B-T (timestamp but NO DSS) still attempts a bounded live OCSP.
    const hasEmbeddedRevocation =
      dssOutcome.data !== undefined &&
      ((dssOutcome.data.ocsps?.length ?? 0) > 0 || (dssOutcome.data.crls?.length ?? 0) > 0);
    let ocsp: VerificationResult['ocsp'] = { status: 'not_checked', source: 'none' };
    if (
      opts.fetchOcsp !== false &&
      path.success &&
      path.matchedRoot &&
      tsaResult.present &&
      !hasEmbeddedRevocation
    ) {
      const issuerCert = path.chain[1]; // signer's issuer = next cert in chain
      if (issuerCert) {
        phase('ocsp');
        ocsp = await checkOcsp({
          signerCert: cms.signerCert,
          issuerCert,
          acSlug: path.matchedRoot.slug,
        });
      }
    }

    // Compute final status. Crypto failures (hash mismatch, sig invalid,
    // OCSP-revoked) are hard 'invalid'. Real chain failures (cert NOT covered
    // by usable real roots) are also 'invalid'. But chain failures caused
    // SOLELY by all roots being placeholders are 'warning' — the PWA renders
    // a DEMO banner explaining the trust anchor is provisional.
    // A revocation only defeats the signature if it happened at or before the
    // time the signature is proven to exist (verified timestamp, else now).
    // A later revocation (e.g. the holder left the company) leaves a properly
    // timestamped signature valid. No revocation date → fail closed.
    const revocationCutoff = proofOfExistence ?? new Date();
    const revokedBeforeProof = (at: Date | undefined): boolean =>
      at === undefined || at.getTime() <= revocationCutoff.getTime();
    const liveRevokedAt =
      ocsp?.status === 'revoked' && ocsp.revokedAt ? new Date(ocsp.revokedAt) : undefined;
    let revokedAfterSigning = ocsp?.status === 'revoked' && !revokedBeforeProof(liveRevokedAt);

    let status: Status;
    if (!docCheck.matches) status = 'invalid';
    else if (!sigValid) status = 'invalid';
    else if (path.keyUsageNotSigning) {
      status = 'invalid';
      warnings.push({
        code: 'key_usage_not_signing',
        message:
          'El certificado del firmante no está autorizado para firmar documentos: su uso de clave no incluye firma digital ni no repudio.',
      });
    } else if (!path.success && !trustInconclusive && path.chainIncomplete) {
      // SECURITY (2026-08-05 CRITICAL fix, was a BLOCK finding): the
      // leaf→root walk got stuck on a missing link. That link is chosen from
      // a pool that includes `intermediates` the SIGNER embedded in the
      // CMS — attacker-controlled input. An attacker can mint a rogue CA,
      // sign a leaf with it, and simply omit the rogue CA from the PDF; the
      // walk then gets stuck for the exact same reason a legitimate
      // not-yet-bundled ACE intermediate would. `chainIncomplete` therefore
      // CANNOT be trusted to soften the verdict — only pkijs's rejection
      // matters, so this stays the SAME hard rejection as `untrusted_root`.
      // What differs is only the MESSAGE: honest about the two possible
      // causes (a real gap in our bundle, or an unaccredited issuer) without
      // outright accusing the user of fraud, and without implying the
      // signature might still be trustworthy.
      status = 'invalid';
      warnings.push({
        code: 'CHAIN_INCOMPLETE_UNKNOWN_INTERMEDIATE',
        message:
          'No pudimos completar la cadena de confianza de este certificado: puede faltar una autoridad certificadora intermedia que esta versión de firmar.ec todavía no reconoce, o el certificado no proviene de una entidad acreditada por ARCOTEL. Si crees que esto es un error, actualiza la aplicación.',
      });
    } else if (
      !path.success &&
      !trustInconclusive &&
      !isWithinValidity(cms.signerCert, proofOfExistence ?? new Date()) &&
      !(declaredSigningTime && isWithinValidity(cms.signerCert, declaredSigningTime))
    ) {
      // Outside its validity both at the proven/current time and at the date
      // the signer declared: say so, instead of blaming the issuer.
      status = 'invalid';
      warnings.push({
        code: 'signer_cert_not_valid',
        message:
          'El certificado del firmante no estaba vigente en la fecha de la firma (caducado o todavía no emitido).',
      });
    } else if (!path.success && !trustInconclusive) {
      status = 'invalid';
      warnings.push({
        code: 'untrusted_root',
        message:
          'El certificado del firmante no encadena con ninguna ACE acreditada por ARCOTEL en la TSL-EC. La firma es criptográficamente correcta pero no proviene de un emisor reconocido en Ecuador.',
      });
    } else if (ocsp?.status === 'revoked' && revokedBeforeProof(liveRevokedAt)) {
      status = 'invalid';
      warnings.push({
        code: 'cert_revoked',
        message:
          'El certificado del firmante fue revocado por la ACE emisora antes o en el momento de la firma.',
      });
    } else if (trustInconclusive) {
      status = 'warning';
      warnings.push({
        code: 'TRUST_PLACEHOLDER',
        message:
          'ARCOTEL TSL roots are placeholders; cryptographic checks passed but the trust chain is provisional (not yet binding).',
      });
    } else if (sig.hasIncrementalUpdates && isLatestSignature && !appendedBytesAreDocTimeStamp) {
      // Only flag for the LATEST signature — in multi-sig PDFs the "bytes after"
      // earlier signatures are subsequent legitimate signatures (PAdES
      // incremental updates), not document tampering. v0.7.29: a PAdES B-LTA
      // document timestamp wrap appended after the user signature is also a
      // legitimate incremental update, not tampering.
      status = 'warning';
      warnings.push({
        code: 'incremental_updates',
        message: 'PDF has bytes appended after the signature; signature does not cover them.',
      });
    } else if (ocsp?.status === 'unknown') {
      // Only warn when the responder actually returned an ambiguous status.
      // 'not_checked' means we deliberately skipped (B-B profile or fetch
      // disabled) — not a finding worth surfacing.
      status = 'warning';
      warnings.push({
        code: 'ocsp_unavailable',
        message: 'OCSP responder did not return a definitive status for this certificate.',
      });
    } else {
      status = 'valid';
    }

    // Legacy weak hash (SHA-1, no-signedAttrs path): the signature verifies and
    // the cert chains to an accredited ACE, but SHA-1 is cryptographically weak.
    // Never report a bare 'valid' — downgrade to 'warning' and explain.
    if (weakSha1) {
      if (status === 'valid') status = 'warning';
      warnings.push({
        code: 'weak_hash_sha1',
        message:
          'La firma usa SHA-1, un algoritmo de hash obsoleto y criptográficamente débil (no cumple los estándares actuales). La firma es verificable y el certificado encadena a una ACE acreditada por ARCOTEL, pero su robustez es limitada.',
      });
    }

    if (signingTimeUnproven) {
      if (status === 'valid') status = 'warning';
      warnings.push({
        code: 'signing_time_unproven',
        message:
          'La cadena de certificados no es válida hoy y ningún sello de tiempo válido prueba cuándo se firmó: solo se valida en la fecha que declara el propio firmante, que no puede comprobarse. Es válida únicamente si de verdad se firmó en esa fecha.',
      });
    }

    // Forward TSL diagnostic warnings (placeholder list, fingerprint mismatches).
    for (const w of path.warnings ?? []) warnings.push({ code: 'tsl_warning', message: w });

    // F6: surface a non-fatal warning when a token is present but didn't
    // verify (silver). Outer signature status is unchanged — the warning is
    // purely informational and drives PWA UI badge state.
    if (tsaResult.present && !tsaResult.valid) {
      warnings.push({
        code: 'timestamp_invalid',
        message: `RFC 3161 timestamp present but failed verification (${tsaResult.reason ?? 'unknown'}).`,
      });
    }

    // F7 — verifyLtv runs after path validation so we can pass the chain.
    // Always runs (even when DSS absent) to detect document timestamps.
    phase('ltv');
    // Hard deadline (v0.7.39): LTV is purely informational and NEVER changes
    // the outer signature validity (spec §6.4). On a mobile CPU it can still
    // hang — the v0.7.38 size-cap + Date.now() budget only bound SYNCHRONOUS
    // work; an `await` that never settles (e.g. the B-LTA document-timestamp
    // crypto, or a slow parse inside an awaited call) slips past them and the
    // 30s watchdog fires (`verify:#5 ltv` persisted through 0.7.36–0.7.38).
    // Racing verifyLtv against a wall-clock deadline guarantees the phase
    // returns regardless of what stalls inside, degrading to a DSS-presence
    // summary with an `ltv_timeout` note.
    const ltvSummary = await Promise.race([
      verifyLtv(path.chain ?? [], dssOutcome.data, sig.contents, pdfBytes),
      new Promise<import('./ltv').LtvSummary>((resolve) =>
        setTimeout(() => {
          const d = dssOutcome.data;
          const ocspN = d?.ocsps?.length ?? 0;
          const crlN = d?.crls?.length ?? 0;
          resolve({
            profile: ocspN > 0 || crlN > 0 ? 'B-LT' : 'B-T',
            dssPresent: d !== undefined,
            embeddedOcspCount: ocspN,
            embeddedCrlCount: crlN,
            retrospectiveValid: false,
            errors: [
              'ltv_timeout: validación de revocación a largo plazo excedió el tiempo en este dispositivo',
            ],
          });
        }, 12_000),
      ),
    ]);
    // Embedded (DSS) revocation evidence, authenticated inside verifyLtv, now
    // affects the verdict too — before, it only produced an ltv_warning and a
    // revoked signer could still come out `valid`.
    const embeddedRevocation = ltvSummary.signerRevocation;
    if (embeddedRevocation && status !== 'invalid') {
      if (revokedBeforeProof(embeddedRevocation.revokedAt)) {
        status = 'invalid';
        warnings.push({
          code: 'cert_revoked',
          message:
            'El certificado del firmante fue revocado por la ACE emisora antes o en el momento de la firma.',
        });
      } else {
        revokedAfterSigning = true;
      }
    }
    if (revokedAfterSigning) {
      if (status === 'valid') status = 'warning';
      warnings.push({
        code: 'revoked_after_signing',
        message:
          'El certificado del firmante fue revocado después de la fecha probada de la firma. La firma era válida cuando se selló.',
      });
    }

    for (const err of ltvSummary.errors) {
      warnings.push({ code: 'ltv_warning', message: err });
    }

    // Profile state machine: pick the highest profile achieved.
    // F6 baseline is B-T (timestamp valid) or B-B (no timestamp); F7 may
    // upgrade to B-LT (DSS material) or B-LTA (document timestamp + DSS).
    // Critical regression guard (rule §9): NEVER downgrade B-T when DSS
    // absent — the timestamp-derived profile floor stays B-T.
    const tsaProfile: 'B-T' | 'B-B' = tsaResult.present && tsaResult.valid ? 'B-T' : 'B-B';
    const ltvProfile = ltvSummary.profile;
    const profileRank: Record<typeof ltvProfile, number> = {
      'B-B': 0,
      'B-T': 1,
      'B-LT': 2,
      'B-LTA': 3,
    };
    const finalProfile: 'B-B' | 'B-T' | 'B-LT' | 'B-LTA' =
      profileRank[ltvProfile] > profileRank[tsaProfile] ? ltvProfile : tsaProfile;

    const subjFp = toHex(
      await digest('SHA-256', new Uint8Array(cms.signerCert.toSchema().toBER(false))),
    );

    const result: VerificationResult = {
      status,
      signer: {
        cert: {
          subject: subjectInfo(cms.signerCert),
          issuer: issuerInfo(cms.signerCert),
          serialNumberHex: toHex(
            new Uint8Array(cms.signerCert.serialNumber.valueBlock.valueHex as ArrayBuffer),
          ),
          validFrom: cms.signerCert.notBefore.value.toISOString(),
          validUntil: cms.signerCert.notAfter.value.toISOString(),
          fingerprintSha256: subjFp,
        },
        identity: ecCertIdentity(cms.signerCert),
      },
      signature: {
        // F6/F7: timestamp baseline + LTV upgrade. Highest tier wins.
        profile: finalProfile,
        digestAlgo: cms.digestAlgoOid,
        signatureAlgo: cms.signatureAlgoOid,
        timestamp: {
          present: tsaResult.present,
          valid: tsaResult.valid,
          badge: tsaResult.badge,
          ...(tsaResult.signingTime ? { signingTime: tsaResult.signingTime.toISOString() } : {}),
          ...(tsaResult.tsaIssuer ? { tsaIssuer: tsaResult.tsaIssuer } : {}),
          ...(tsaResult.reason ? { reason: tsaResult.reason } : {}),
        },
        ltv: ltvSummary,
      },
      ocsp,
      integrity: {
        digestMatches: docCheck.matches,
        hasIncrementalUpdates: sig.hasIncrementalUpdates,
        coveredBytes: sig.byteRange[1] + sig.byteRange[3],
        totalBytes: pdfBytes.length,
      },
      warnings,
      engineVersion: ENGINE_VERSION,
      verifiedAt,
    };

    // Conditional spreads for exactOptionalPropertyTypes
    if (path.matchedRoot?.slug !== undefined)
      result.signer!.matchedRootSlug = path.matchedRoot.slug;
    if (path.matchedRoot?.commonName !== undefined)
      result.signer!.matchedRootName = path.matchedRoot.commonName;
    if (cms.signingTime !== undefined)
      result.signature!.signingTime = cms.signingTime.toISOString();
    if (sig.reason !== undefined) result.signature!.reason = sig.reason;
    if (sig.location !== undefined) result.signature!.location = sig.location;
    if (sig.contactInfo !== undefined) result.signature!.contactInfo = sig.contactInfo;

    return result;
  } catch (e) {
    const code = e instanceof VerificationError ? e.code : 'unknown';
    return {
      status: 'invalid',
      warnings,
      engineVersion: ENGINE_VERSION,
      verifiedAt,
      error: `${code}: ${(e as Error).message}`,
    };
  }
}

/**
 * Verify the FIRST signature in the PDF (back-compat). For multi-firma PDFs
 * use {@link verifyAllSignatures} which returns every signature independently.
 */
export async function verifyPdf(
  pdfBytes: Uint8Array,
  opts: VerifyOptions = {},
): Promise<VerificationResult> {
  const verifiedAt = new Date().toISOString();
  try {
    const sig = await findSignature(pdfBytes);
    if (!sig) {
      return { status: 'no_signature', warnings: [], engineVersion: ENGINE_VERSION, verifiedAt };
    }
    const roots = opts.trustRoots ?? (await getTrustRoots());
    return verifyOneSignature(pdfBytes, sig, opts, roots, verifiedAt);
  } catch (e) {
    const code = e instanceof VerificationError ? e.code : 'unknown';
    return {
      status: 'invalid',
      warnings: [],
      engineVersion: ENGINE_VERSION,
      verifiedAt,
      error: `${code}: ${(e as Error).message}`,
    };
  }
}

/**
 * Aggregate verification result for a PDF containing N signatures (N >= 0).
 * Each entry in `signatures` is a full {@link VerificationResult} for one
 * signature, in document order (chronological signing order).
 *
 * `overallStatus` rules (worst-case across all signatures):
 *   - `no_signature`  → 0 signatures.
 *   - `invalid`       → at least one signature has status='invalid'.
 *   - `warning`       → no invalid, but at least one has status='warning'.
 *   - `valid`         → all signatures have status='valid'.
 */
export interface MultiVerificationResult {
  signatureCount: number;
  signatures: VerificationResult[];
  overallStatus: Status;
  engineVersion: string;
  verifiedAt: string;
}

/**
 * Verify EVERY PAdES signature in the PDF. Each signature is validated
 * independently (its own cert chain, OCSP, TSA, LTV) so a partially-valid
 * multi-firma PDF reports per-signature status.
 *
 * Use this in the UI when the PDF may have been signed by more than one
 * party. For single-sig PDFs the result equals `[verifyPdf()]`.
 */
export async function verifyAllSignatures(
  pdfBytes: Uint8Array,
  opts: VerifyOptions = {},
  /**
   * Optional fine-grained progress hook. The verify Web Worker passes a
   * callback that posts a `progress` message per phase. Two reasons this
   * matters on mobile (v0.7.35):
   *  1. The bus watchdog RESETS on every progress message, so a slow-but-alive
   *     verification (mobile CPUs parse the large ARCOTEL CRLs embedded in a
   *     B-LTA DSS far slower than desktop V8 — easily tens of seconds) no
   *     longer trips the 30s deadline as long as no SINGLE phase exceeds it.
   *  2. The phase label is surfaced in the timeout error's `last stage:` field,
   *     so a phase that genuinely hangs is pinpointed (cms/tsa/chain/ocsp/ltv)
   *     instead of the opaque `verify`.
   * NOT part of {@link VerifyOptions} because a function cannot cross the
   * worker postMessage boundary — it is supplied locally inside the worker.
   */
  onProgress?: (stage: string) => void,
): Promise<MultiVerificationResult> {
  const verifiedAt = new Date().toISOString();
  try {
    onProgress?.('verify:scan');
    const allSigs = await findAllSignatures(pdfBytes);
    // v0.7.29 — PAdES B-LTA document timestamps (/SubFilter /ETSI.RFC3161)
    // are NOT user signatures: they're RFC 3161 TimeStampTokens wrapping the
    // prior /Contents as an incremental update. The verifier already surfaces
    // them via the per-signer `signature.timestamp` + LTV scan (`verifyLtv`),
    // so they must not appear as a separate "Firma inválida" entry nor pollute
    // the intermediate pool (freetsa/ECC chains were causing the real signer
    // to lose its matched ARCOTEL root). Filter them out of the user-signature
    // list before pooling + per-sig verification.
    const sigs = allSigs.filter((s) => s.subFilter !== 'ETSI.RFC3161');
    if (sigs.length === 0) {
      return {
        signatureCount: 0,
        signatures: [],
        overallStatus: 'no_signature',
        engineVersion: ENGINE_VERSION,
        verifiedAt,
      };
    }
    const roots = opts.trustRoots ?? (await getTrustRoots());

    // v0.7.16 — Multi-sig intermediate pooling. Parse every signature's CMS
    // upfront and collect all non-signer certificates. When a signer omits the
    // chain in its own CMS (real case: Magaly's sig in iCert-EC judicial PDFs),
    // we can still build the path using intermediates carried by sibling
    // signatures in the same PDF.
    const allIntermediates: import('pkijs').Certificate[] = [];
    for (const sig of sigs) {
      try {
        const cms = await parseCms(sig.contents);
        // Only the CA certs a sibling embedded: another signer's leaf can never
        // be an issuer here, it just adds noise to the chain pool.
        allIntermediates.push(...cms.intermediates);
      } catch {
        // ignore — verifyOneSignature will surface the parse error per-sig
      }
    }
    const pooledIntermediates = mergeCertsDedup(allIntermediates);

    // The "latest" signature is the one whose covered byte range extends
    // furthest into the file (largest c+d). Earlier sigs always have bytes
    // after them (subsequent legitimate sigs) and must NOT be flagged with
    // `incremental_updates`. Compare against ALL signatures including the
    // document timestamp — the DTS appended at EOF means the user sig before
    // it is correctly NOT the latest, but its appended bytes are the DTS
    // (legitimate), so we treat it as latest for incremental_updates purposes.
    let latestEnd = -1;
    for (const s of allSigs) {
      const end = s.byteRange[2] + s.byteRange[3];
      if (end > latestEnd) latestEnd = end;
    }
    let latestIdx = 0;
    let latestSigEnd = -1;
    for (const [i, s] of sigs.entries()) {
      const end = s.byteRange[2] + s.byteRange[3];
      if (end > latestSigEnd) {
        latestSigEnd = end;
        latestIdx = i;
      }
    }
    // DocTimeStamp metadata: byte-ranges of /ETSI.RFC3161 sigs (B-LTA wraps).
    // Used to suppress spurious `incremental_updates` warnings on the user
    // sig that the DTS legitimately follows.
    const dtsSigs = allSigs.filter((s) => s.subFilter === 'ETSI.RFC3161');
    // v0.7.41 — verify signatures SEQUENTIALLY, not via Promise.all.
    // Why: each signature's LTV phase does heavy SYNCHRONOUS work (pkijs parses,
    // findDocumentTimestamps scan). Under Promise.all all N signatures emit
    // their `ltv` progress beacon almost simultaneously, then execute their
    // synchronous work back-to-back on the single worker thread with NO beacon
    // in between — a sync storm whose cumulative time crosses the 30s watchdog
    // (observed: a 6-signature B-LTA PDF reached sig #5 then froze). Running
    // sequentially brackets EACH signature's synchronous work between its own
    // beacons, so the watchdog resets between signatures and only per-signature
    // time matters (bounded by the CRL/OCSP caps + LTV deadline). Multi-sig
    // PDFs are rare and small in count, so the lost parallelism is negligible.
    const results: VerificationResult[] = [];
    for (const [i, sig] of sigs.entries()) {
      // The bytes appended right after this user sig are accounted for by a
      // DTS iff some DTS's coverage starts exactly where this sig ends and
      // its coverage reaches EOF. PAdES DTS has byteRange [0, b, c, d] where
      // b coincides with the sig dict gap and the DTS covers everything up
      // to a+b (user-sig end). We check that any DTS exists with its
      // byteRange starting at offset 0 and ending at or past EOF — that's
      // the canonical B-LTA wrap.
      const sigEnd = sig.byteRange[2] + sig.byteRange[3];
      const wrappedByDts = dtsSigs.some((dts) => {
        const dtsEnd = dts.byteRange[2] + dts.byteRange[3];
        // DTS appears after this user sig and reaches EOF.
        return dts.byteRange[1] >= sigEnd - 4 && dtsEnd >= pdfBytes.length - 4;
      });
      // eslint-disable-next-line no-await-in-loop -- sequential is intentional (see comment above)
      const r = await verifyOneSignature(
        pdfBytes,
        sig,
        opts,
        roots,
        verifiedAt,
        pooledIntermediates,
        i === latestIdx,
        wrappedByDts,
        onProgress,
        sigs.length > 1 ? i : undefined,
      );
      results.push(r);
    }
    // Compute aggregate status — worst-case wins.
    const rank: Record<Status, number> = {
      valid: 0,
      warning: 1,
      no_signature: 2,
      invalid: 3,
    };
    const overallStatus = results.reduce<Status>(
      (acc, r) => (rank[r.status] > rank[acc] ? r.status : acc),
      'valid',
    );
    return {
      signatureCount: results.length,
      signatures: results,
      overallStatus,
      engineVersion: ENGINE_VERSION,
      verifiedAt,
    };
  } catch (e) {
    const code = e instanceof VerificationError ? e.code : 'unknown';
    // Pre-iteration error (bad PDF header, malformed /ByteRange): surface as
    // a single 'invalid' aggregate so the caller has a deterministic shape.
    return {
      signatureCount: 0,
      signatures: [
        {
          status: 'invalid',
          warnings: [],
          engineVersion: ENGINE_VERSION,
          verifiedAt,
          error: `${code}: ${(e as Error).message}`,
        },
      ],
      overallStatus: 'invalid',
      engineVersion: ENGINE_VERSION,
      verifiedAt,
    };
  }
}
