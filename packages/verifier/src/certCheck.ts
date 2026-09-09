/**
 * certCheck.ts — standalone certificate validation (no PDF, no signing).
 *
 * Powers the "Validar Certificado" PWA page: the user uploads a .p12/.pfx,
 * the signer extracts the leaf + intermediates as DER, and this function
 * reports who the cert belongs to, who issued it, whether it chains to a
 * real (non-placeholder) ARCOTEL-accredited root, its validity window, and
 * — when `checkRevocation` is set — its live OCSP/CRL revocation status.
 *
 * Mirrors FirmaEC 5.1.0's "Validar Certificado" tab (titular split into
 * nombres/apellidos + cédula, plus Expirado / Revocado states). It reuses the
 * same internal `validatePath` engine used by the PDF verifier so the trust
 * decision is identical to a signature's chain check, and the same
 * `@firma-ec/ltv-validation` OCSP→CRL cascade the signer uses for LTV.
 */

import {
  ecCertIdentity,
  issuerInfo,
  resolveIssuerCert,
  subjectInfo,
  toHex,
} from '@firma-ec/crypto-core';
import {
  ARCOTEL_PROXY_MAP,
  type ParsedCert,
  type ProxyMap,
  fetchCrl,
  fetchOcsp,
  isCertRevoked,
} from '@firma-ec/ltv-validation';
import {
  type TrustIntermediate,
  type TrustRoot,
  getIntermediates,
  getTrustRoots,
} from '@firma-ec/tsl-ec';
import { fromBER } from 'asn1js';
import { Certificate } from 'pkijs';
import { validatePath } from './pathValidation';

/** Live revocation outcome. `unchecked` means no network check was requested. */
export type CertRevocationStatus = 'good' | 'revoked' | 'unknown' | 'unchecked';

export interface CertCheckResult {
  subjectCN: string;
  issuerCN: string;
  /**
   * Holder's cédula. Resolved by `ecCertIdentity`, which reads each ACE's
   * private OID arc — the subject serialNumber RDN (2.5.4.5) is absent or
   * holds an unrelated value depending on the issuer.
   */
  cedula?: string;
  /** Holder's RUC (13 digits) when the certificate publishes one. */
  ruc?: string;
  /** Given names — from the ACE arc, falling back to the DN (OID 2.5.4.42). */
  givenName?: string;
  /** Surnames — from the ACE arc, falling back to the DN (OID 2.5.4.4). */
  surname?: string;
  /**
   * Company the holder represents, as published by the ACE. Present only on
   * legal-representative certificates — for those, `ruc` is the company's.
   */
  organization?: string;
  /** Role the holder signs under (REPRESENTANTE LEGAL, GERENTE GENERAL, …). */
  jobTitle?: string;
  serialHex: string;
  notBefore: string; // ISO string
  notAfter: string; // ISO string
  validityStatus: 'valid' | 'expired' | 'not_yet_valid';
  /** Chains to a real (non-placeholder) ARCOTEL-accredited root. */
  trusted: boolean;
  matchedAceSlug?: string;
  matchedAceOrg?: string;
  /** Live revocation status. 'unchecked' when `checkRevocation` was off. */
  revocationStatus: CertRevocationStatus;
  /** Mechanism that produced the determination. */
  revocationVia?: 'ocsp' | 'crl';
  /** ISO date the cert was revoked (only when status === 'revoked'). */
  revokedAt?: string;
  /** Diagnostic detail when status is 'unknown' (e.g. 'no_aia', 'network'). */
  revocationDetail?: string;
  warnings: string[];
}

export interface CertCheckOptions {
  /** Override the TSL roots; default fetched from @firma-ec/tsl-ec. */
  trustRoots?: TrustRoot[] | undefined;
  /**
   * Override the bundled subordinate-CA intermediates used to complete the
   * chain when the uploaded .p12 carries only the leaf. Default fetched from
   * @firma-ec/tsl-ec. Not trust anchors — they only bridge a leaf to an
   * already-trusted root. Pass `[]` to disable.
   */
  trustIntermediates?: TrustIntermediate[] | undefined;
  /** Reference time for validity + chain checks; defaults to now. */
  atTime?: Date | undefined;
  /** When true, perform a live OCSP→CRL revocation check against ARCOTEL. */
  checkRevocation?: boolean | undefined;
  /** Same-origin proxy map for OCSP/CRL upstreams. Defaults to
   *  ARCOTEL_PROXY_MAP. Pass `null` to disable proxying (direct fetch). */
  proxyMap?: ProxyMap | null | undefined;
  /** Per-request network timeout (ms). Default 8000. */
  revocationTimeoutMs?: number | undefined;
  /** fetch implementation override (for deterministic tests). */
  fetchImpl?: typeof globalThis.fetch | undefined;
}

/** Strip PEM armor and return the DER bytes. */
function pemToDer(pem: string): Uint8Array {
  const b64 = pem.replace(/-----BEGIN [A-Z ]+-----|-----END [A-Z ]+-----|\s/g, '');
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

/** Decode a DER-encoded X.509 certificate into a pkijs Certificate. */
function derToCert(der: Uint8Array): Certificate {
  const asn = fromBER(
    der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength) as ArrayBuffer,
  );
  if (asn.offset === -1) throw new Error('DER ASN.1 decode failed');
  return new Certificate({ schema: asn.result });
}

/** Build the minimal ParsedCert the LTV layer needs from a parsed cert + its DER. */
function toLtvParsedCert(cert: Certificate, der: Uint8Array): ParsedCert {
  return {
    subjectCN: subjectInfo(cert).cn ?? null,
    issuerCN: issuerInfo(cert).cn ?? null,
    der,
    notBefore: cert.notBefore.value,
    notAfter: cert.notAfter.value,
  };
}

interface RevocationOutcome {
  status: CertRevocationStatus;
  via?: 'ocsp' | 'crl';
  revokedAt?: string;
  detail?: string;
}

/**
 * Live OCSP-first / CRL-fallback revocation check for the leaf certificate.
 *
 * Mirrors the signer's `collectLtvData` cascade (spec §5.2): OCSP `revoked` /
 * `good` is authoritative; OCSP `unknown` or any transport failure falls back
 * to a CRL lookup; if neither yields a determination the status is `unknown`
 * (e.g. offline, or the cert exposes no AIA/CDP). Never throws.
 */
async function checkRevocationLive(
  leaf: ParsedCert,
  issuer: ParsedCert | null,
  opts: CertCheckOptions,
): Promise<RevocationOutcome> {
  const proxyMap = opts.proxyMap === null ? undefined : (opts.proxyMap ?? ARCOTEL_PROXY_MAP);
  const timeoutMs = opts.revocationTimeoutMs ?? 8000;
  const fetchImpl = opts.fetchImpl;

  let lastDetail = 'no_issuer';

  // OCSP requires the issuer cert for the CertID hash.
  if (issuer) {
    const ocsp = await fetchOcsp(leaf, issuer, {
      timeoutMs,
      ...(proxyMap ? { proxyMap } : {}),
      ...(fetchImpl ? { fetchImpl } : {}),
    });
    if (ocsp.ok) {
      if (ocsp.status === 'revoked') {
        return {
          status: 'revoked',
          via: 'ocsp',
          ...(ocsp.revokedAt ? { revokedAt: ocsp.revokedAt.toISOString() } : {}),
        };
      }
      if (ocsp.status === 'good') return { status: 'good', via: 'ocsp' };
      lastDetail = 'ocsp_unknown';
    } else {
      lastDetail = `ocsp_${ocsp.reason}`;
    }
  }

  // CRL fallback.
  const crl = await fetchCrl(leaf, {
    timeoutMs,
    ...(issuer ? { issuerCert: issuer } : {}),
    ...(proxyMap ? { proxyMap } : {}),
    ...(fetchImpl ? { fetchImpl } : {}),
  });
  if (crl.ok) {
    const rev = isCertRevoked(leaf, crl.crl);
    if (rev.revoked) {
      return {
        status: 'revoked',
        via: 'crl',
        ...(rev.revokedAt ? { revokedAt: rev.revokedAt.toISOString() } : {}),
        ...(rev.reason ? { detail: rev.reason } : {}),
      };
    }
    return { status: 'good', via: 'crl' };
  }

  return { status: 'unknown', detail: issuer ? `crl_${crl.reason}` : lastDetail };
}

/**
 * Validate a single certificate (leaf) against the ARCOTEL TSL-EC roots.
 *
 * @param certDer          DER bytes of the leaf certificate.
 * @param intermediatesDer DER bytes of any intermediate CA certs.
 * @param opts             trustRoots / atTime / revocation overrides.
 */
export async function checkCertificate(
  certDer: Uint8Array,
  intermediatesDer: Uint8Array[],
  opts: CertCheckOptions = {},
): Promise<CertCheckResult> {
  const atTime = opts.atTime ?? new Date();
  const cert = derToCert(certDer);
  const intermediates = intermediatesDer.map(derToCert);
  // DERs aligned 1:1 with `intermediates`. As bundled bridging CAs are appended
  // below, their DER must be pushed here too — the revocation path indexes this
  // array to build the issuer's OCSP CertID, and an index past the original
  // `intermediatesDer` yields an undefined DER → crash (leaf-only .p12 case).
  const intermediateDers: Uint8Array[] = [...intermediatesDer];
  const roots = opts.trustRoots ?? (await getTrustRoots());

  // Bundled subordinate-CA intermediates (e.g. UANATACA CA2 2016) complete the
  // chain when the uploaded .p12 ships leaf-only. Not trust anchors — they only
  // bridge a leaf to an already-trusted root (validatePath still requires a
  // self-signed root match), so they can never make an untrusted cert trusted.
  // Add ONLY the links that bridge THIS cert's chain (dumping the whole bundle
  // pollutes pkijs's pool with orphan CAs and can break valid chains).
  const bundledIntermediates = opts.trustIntermediates ?? (await getIntermediates());
  const bundleCerts: { cert: Certificate; der: Uint8Array }[] = [];
  for (const it of bundledIntermediates) {
    try {
      const der = pemToDer(it.pemContent);
      bundleCerts.push({ cert: derToCert(der), der });
    } catch {
      /* skip unparseable */
    }
  }
  const pool = [cert, ...intermediates];
  let cur: Certificate | undefined = cert;
  for (let depth = 0; depth < 8 && cur !== undefined; depth++) {
    if (cur.subject.isEqual(cur.issuer)) break;
    // 2026-08-23 fix: mismo criterio que el bundle de abajo — el pool (certs
    // embebidos en el CMS) puede traer dos homónimas de una renovación; el
    // `.find()` plano seguía la primera embebida. resolveIssuerCert elige la
    // emisora real; si ninguna homónima resuelve, se cae al bundle.
    const inPool = await resolveIssuerCert(cur, pool);
    if (inPool) {
      if (inPool === cur) break;
      cur = inPool;
      continue;
    }
    // 2026-08-05 HIGH fix: mirrors selectBridgingIntermediates in index.ts —
    // bundleCerts can hold several intermediates sharing a subject DN (e.g.
    // BCE's 2011/2019 subCA renewal); resolve by AKI/SKI, not declaration order.
    const matchedCert = await resolveIssuerCert(
      cur,
      bundleCerts.map((bc) => bc.cert),
    );
    const match = matchedCert && bundleCerts.find((bc) => bc.cert === matchedCert);
    if (!match) break;
    intermediates.push(match.cert);
    intermediateDers.push(match.der);
    pool.push(match.cert);
    cur = match.cert;
  }

  const path = await validatePath(cert, intermediates, roots, atTime);

  const subj = subjectInfo(cert);
  const iss = issuerInfo(cert);

  const notBefore = cert.notBefore.value;
  const notAfter = cert.notAfter.value;

  let validityStatus: CertCheckResult['validityStatus'];
  if (atTime < notBefore) validityStatus = 'not_yet_valid';
  else if (atTime > notAfter) validityStatus = 'expired';
  else validityStatus = 'valid';

  const warnings = [...path.warnings];

  // Live revocation (OCSP→CRL) when requested.
  let revocation: RevocationOutcome = { status: 'unchecked' };
  if (opts.checkRevocation) {
    const leafParsed = toLtvParsedCert(cert, certDer);
    const issuerParsed =
      intermediates
        .map((c, i) => toLtvParsedCert(c, intermediateDers[i]!))
        .find((c) => c.subjectCN !== null && c.subjectCN === leafParsed.issuerCN) ?? null;
    revocation = await checkRevocationLive(leafParsed, issuerParsed, opts);
    if (revocation.status === 'revoked') warnings.push('cert_revoked');
    else if (revocation.status === 'unknown') {
      warnings.push(`revocation_unknown: ${revocation.detail ?? 'unverifiable'}`);
    }
  }

  const result: CertCheckResult = {
    subjectCN: subj.cn ?? '',
    issuerCN: iss.cn ?? '',
    serialHex: toHex(new Uint8Array(cert.serialNumber.valueBlock.valueHex as ArrayBuffer)),
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
    validityStatus,
    trusted: path.success,
    revocationStatus: revocation.status,
    warnings,
  };

  // Conditional spreads for exactOptionalPropertyTypes
  const identity = ecCertIdentity(cert);
  if (identity.cedula !== undefined) result.cedula = identity.cedula;
  if (identity.ruc !== undefined) result.ruc = identity.ruc;
  if (identity.givenName !== undefined) result.givenName = identity.givenName;
  if (identity.surname !== undefined) result.surname = identity.surname;
  if (identity.organization !== undefined) result.organization = identity.organization;
  if (identity.jobTitle !== undefined) result.jobTitle = identity.jobTitle;
  if (path.matchedRoot?.slug !== undefined) result.matchedAceSlug = path.matchedRoot.slug;
  if (path.matchedRoot?.orgName !== undefined) result.matchedAceOrg = path.matchedRoot.orgName;
  if (revocation.via !== undefined) result.revocationVia = revocation.via;
  if (revocation.revokedAt !== undefined) result.revokedAt = revocation.revokedAt;
  if (revocation.detail !== undefined) result.revocationDetail = revocation.detail;

  return result;
}
