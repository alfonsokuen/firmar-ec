/**
 * OCSP response parser per RFC 6960.
 *
 * Returns a structured view of the BasicOCSPResponse:
 *   - certId: hex-encoded {issuerNameHash, issuerKeyHash, serialNumber}
 *   - certStatus: 'good' | 'revoked' | 'unknown'
 *   - thisUpdate / nextUpdate / revokedAt / producedAt
 *   - signatureValid: signature over tbsResponseData verified against the
 *     ACTUAL signer (delegate or issuer), gated by chain trust AND — for a
 *     delegate — the id-kp-OCSPSigning EKU (pkijs's own `.verify()` checks
 *     neither the EKU nor which SingleResponse belongs to the caller's cert;
 *     this module closes both gaps).
 *   - responderCert: the cert that actually signed the response, when one
 *     was attached (delegate, or issuer re-attaching itself); null when the
 *     issuer signed directly without an attached cert.
 *
 * Browser-compatible: uses asn1js + pkijs + globalThis.crypto.subtle only.
 *
 * SECURITY — why `expected` is mandatory: an OCSP responder that is genuinely
 * trusted by `issuerCert` can still be replayed against the WRONG certificate
 * (a MITM captures a real `good` response for cert A and serves it back when
 * we ask about cert B, same issuer). `signatureValid` alone does not catch
 * this — the signature is real. The caller must tell us which CertID it
 * expects (`expected.serialHex`, optionally `expected.issuerKeyHashHex`), and
 * we reject any response whose SingleResponse entries don't include a match
 * — see `no_matching_single_response` below.
 */

import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import type { ParsedCert, RevocationStatus } from '../types';
import { type CertIdHashAlgo, certIdHashAlgoFromOid, normalizeSerialHex } from './certid';

const OID_BASIC_OCSP_RESPONSE = '1.3.6.1.5.5.7.48.1.1';
/** id-kp-OCSPSigning */
const OID_OCSP_SIGNING_EKU = '1.3.6.1.5.5.7.3.9';
/** id-pkix-ocsp-nonce */
const OID_OCSP_NONCE = '1.3.6.1.5.5.7.48.1.2';

/** Diagnostic detail constants — literal strings only, never interpolated data (no serial/cert/name leaks). */
const DETAIL_MISSING_EKU = 'responder_missing_ocsp_signing_eku';
const DETAIL_SIGNER_NOT_FOUND = 'responder_certificate_not_found';
const DETAIL_NO_MATCH = 'no_matching_single_response';

export interface ParsedOcspResponse {
  /** Hex of issuerNameHash + issuerKeyHash + serial (concatenated) of the SELECTED SingleResponse. */
  certIdHex: string;
  /** issuerNameHash hex (informational only — never part of the match/reject decision). */
  issuerNameHashHex: string;
  /** issuerKeyHash hex. */
  issuerKeyHashHex: string;
  /** Serial as hex (no leading zero stripping — raw echoed value). */
  serialHex: string;
  /** CertID hashAlgorithm family, derived from the SingleResponse's own OID. */
  certIdHashAlgo: CertIdHashAlgo;
  certStatus: RevocationStatus;
  producedAt: Date;
  thisUpdate: Date;
  nextUpdate?: Date;
  revokedAt?: Date;
  /** CRLReason name (RFC 5280 §5.3.1) of the selected revoked entry, when given. */
  revocationReason?: string;
  signatureValid: boolean;
  /** Literal diagnostic constant for WHY signatureValid is false; never dynamic data. */
  signatureDetail?: string;
  /** The cert that actually signed the response, when attached in the response's certs[]; else null. */
  responderCert: ParsedCert | null;
  /** Whether the responder cert carries the id-kp-OCSPSigning EKU (informational — the real gate is folded into signatureValid). */
  responderHasOcspSigningEku: boolean;
  /** Nonce echoed by the responder (parsed from the response extension), or null when absent. */
  responseNonce: Uint8Array | null;
}

export class OcspParseError extends Error {
  constructor(
    message: string,
    public detail?: string,
    public code?: string,
  ) {
    super(message);
    this.name = 'OcspParseError';
  }
}

interface ExpectedCertId {
  /** Hex of the subject cert's serial, as built for the request (RFC 6960 §4.2.1 — echoed verbatim by a compliant responder). */
  serialHex: string;
  /** Hex of the request's issuerKeyHash. When provided, a SingleResponse must match it too (not just the serial). */
  issuerKeyHashHex?: string;
}

function toAB(u: Uint8Array): ArrayBuffer {
  return u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;
}

function bufToHex(buf: ArrayBuffer | Uint8Array): string {
  const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let out = '';
  for (let i = 0; i < u.length; i++) {
    const b = u[i] ?? 0;
    out += b.toString(16).padStart(2, '0');
  }
  return out;
}

function pkijsCertFromDer(der: Uint8Array): pkijs.Certificate {
  const asn = asn1js.fromBER(toAB(der));
  if (asn.offset === -1) throw new OcspParseError('cert ASN.1 decode failed');
  return new pkijs.Certificate({ schema: asn.result });
}

function parsedCertFromPkijs(c: pkijs.Certificate): ParsedCert {
  const der = new Uint8Array(c.toSchema(true).toBER(false));
  const subjectCN = extractCN(c.subject.typesAndValues);
  const issuerCN = extractCN(c.issuer.typesAndValues);
  return {
    subjectCN,
    issuerCN,
    der,
    notBefore: c.notBefore.value as Date,
    notAfter: c.notAfter.value as Date,
  };
}

function extractCN(
  tv: { type: string; value: { valueBlock: { value?: string } } }[] | undefined,
): string | null {
  if (!tv) return null;
  for (const e of tv) {
    if (e.type === '2.5.4.3') {
      const v = e.value?.valueBlock?.value;
      if (typeof v === 'string') return v;
    }
  }
  return null;
}

function hasOcspSigningEku(cert: pkijs.Certificate): boolean {
  const exts = cert.extensions ?? [];
  for (const ext of exts) {
    if (ext.extnID !== '2.5.29.37') continue; // id-ce-extKeyUsage
    const parsed = ext.parsedValue as { keyPurposes?: string[] } | undefined;
    if (parsed?.keyPurposes?.includes(OID_OCSP_SIGNING_EKU)) return true;
  }
  return false;
}

function spkiHex(cert: pkijs.Certificate): string {
  return bufToHex(new Uint8Array(cert.subjectPublicKeyInfo.toSchema().toBER(false)));
}

/**
 * Does `cert` match the response's `responderID` per RFC 6960 §4.2.2.2's two
 * legal forms — byName (RDN equality) or byKey (SHA-1 of the raw SPKI bit
 * string)? Replicates pkijs's own internal `BasicOCSPResponse.verify` search
 * so we can identify the ACTUAL signer even when it isn't `certs[0]`, and so
 * we can check the issuer directly when `certs[]` is absent.
 */
async function certMatchesResponderId(
  cert: pkijs.Certificate,
  responderID: unknown,
  crypto: pkijs.ICryptoEngine,
): Promise<boolean> {
  if (responderID instanceof pkijs.RelativeDistinguishedNames) {
    return cert.subject.isEqual(responderID);
  }
  if (responderID instanceof asn1js.OctetString) {
    const hash = await crypto.digest(
      { name: 'sha-1' },
      toAB(new Uint8Array(cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView)),
    );
    return bufToHex(hash) === bufToHex(responderID.valueBlock.valueHexView);
  }
  return false;
}

async function findResponderCertIndex(
  certs: pkijs.Certificate[],
  responderID: unknown,
  crypto: pkijs.ICryptoEngine,
): Promise<number> {
  for (let i = 0; i < certs.length; i++) {
    const cert = certs[i];
    if (cert && (await certMatchesResponderId(cert, responderID, crypto))) return i;
  }
  return -1;
}

interface SignerResolution {
  signatureValid: boolean;
  signatureDetail: string | undefined;
  responderPkiCert: pkijs.Certificate | null;
}

/**
 * Resolve the actual signer, verify the signature, and fold the EKU gate in.
 *
 * Two paths, per whether the response attaches `certs[]`:
 *   - certs[] present: find the entry matching responderID (byName/byKey,
 *     same algorithm pkijs uses internally), then verify via pkijs's chain-
 *     validating `basic.verify()` against `issuerCert` as the trust anchor.
 *   - certs[] absent: pkijs's `.verify()` THROWS ("No certificates attached")
 *     instead of falling back to the issuer — a real, measured availability
 *     bug (ArgosData's ACE responder signs directly with the CA key and
 *     omits `certs[]`). When `responderID` matches the issuer itself, verify
 *     directly against the issuer's public key with WebCrypto; anything else
 *     (responderID doesn't match issuer, no cert to check) is `signatureValid
 *     = false` — never a crash.
 *
 * EKU: RFC 6960 §4.2.2.2 only requires id-kp-OCSPSigning on a DELEGATED
 * responder, never on the issuer signing directly. "Delegate" here is decided
 * by SPKI equality against the issuer — not by "was a cert attached" — so an
 * issuer that re-attaches its own cert in certs[] is still exempt.
 */
async function resolveSigner(
  basic: pkijs.BasicOCSPResponse,
  issuerPki: pkijs.Certificate,
): Promise<SignerResolution> {
  const crypto = pkijs.getCrypto(true);
  const certsArr = basic.certs ?? [];
  const responderID = basic.tbsResponseData.responderID;

  let responderPkiCert: pkijs.Certificate | null = null;
  let signatureValid = false;
  let isSelfResponder = false;

  if (certsArr.length > 0) {
    const idx = await findResponderCertIndex(certsArr, responderID, crypto);
    if (idx !== -1) responderPkiCert = certsArr[idx] ?? null;
    try {
      signatureValid = await basic.verify({ trustedCerts: [issuerPki] });
    } catch {
      signatureValid = false;
    }
    if (responderPkiCert) {
      isSelfResponder = spkiHex(responderPkiCert) === spkiHex(issuerPki);
    }
  } else {
    const matchesIssuer = await certMatchesResponderId(issuerPki, responderID, crypto);
    if (matchesIssuer) {
      isSelfResponder = true;
      try {
        signatureValid = await crypto.verifyWithPublicKey(
          toAB(basic.tbsResponseData.tbsView),
          basic.signature,
          issuerPki.subjectPublicKeyInfo,
          basic.signatureAlgorithm,
        );
      } catch {
        signatureValid = false;
      }
    } else {
      return {
        signatureValid: false,
        signatureDetail: DETAIL_SIGNER_NOT_FOUND,
        responderPkiCert: null,
      };
    }
  }

  if (signatureValid && !isSelfResponder) {
    const hasEku = responderPkiCert ? hasOcspSigningEku(responderPkiCert) : false;
    if (!hasEku) {
      return { signatureValid: false, signatureDetail: DETAIL_MISSING_EKU, responderPkiCert };
    }
  }

  return { signatureValid, signatureDetail: undefined, responderPkiCert };
}

interface SingleResponseView {
  single: pkijs.SingleResponse;
  issuerNameHashHex: string;
  issuerKeyHashHex: string;
  serialHex: string;
  certIdHashAlgo: CertIdHashAlgo;
  certStatus: RevocationStatus;
  revokedAt: Date | undefined;
  revocationReason: string | undefined;
  thisUpdate: Date;
  nextUpdate: Date | undefined;
}

const CRL_REASONS = [
  'unspecified',
  'keyCompromise',
  'cACompromise',
  'affiliationChanged',
  'superseded',
  'cessationOfOperation',
  'certificateHold',
  '',
  'removeFromCRL',
  'privilegeWithdrawn',
  'aACompromise',
];

function viewSingleResponse(single: pkijs.SingleResponse): SingleResponseView {
  const certID = single.certID;
  const issuerNameHashHex = bufToHex(
    (certID.issuerNameHash.valueBlock as { valueHex: ArrayBuffer }).valueHex,
  );
  const issuerKeyHashHex = bufToHex(
    (certID.issuerKeyHash.valueBlock as { valueHex: ArrayBuffer }).valueHex,
  );
  const serialHex = bufToHex(
    (certID.serialNumber.valueBlock as { valueHex: ArrayBuffer }).valueHex,
  );
  const certIdHashAlgo = certIdHashAlgoFromOid(certID.hashAlgorithm.algorithmId);

  const cs = single.certStatus as unknown as {
    idBlock?: { tagNumber?: number };
    revocationTime?: { value: Date };
    revocationReason?: { valueBlock?: { valueDec?: number } };
  };
  let certStatus: RevocationStatus = 'unknown';
  let revokedAt: Date | undefined;
  let revocationReason: string | undefined;
  if (cs.idBlock?.tagNumber === 0) certStatus = 'good';
  else if (cs.idBlock?.tagNumber === 1) {
    certStatus = 'revoked';
    revokedAt = cs.revocationTime?.value;
    const code = cs.revocationReason?.valueBlock?.valueDec;
    if (code !== undefined) revocationReason = CRL_REASONS[code] || 'unspecified';
  }

  return {
    single,
    issuerNameHashHex,
    issuerKeyHashHex,
    serialHex,
    certIdHashAlgo,
    certStatus,
    revokedAt,
    revocationReason,
    thisUpdate: single.thisUpdate as Date,
    nextUpdate: single.nextUpdate as Date | undefined,
  };
}

/**
 * Pick the SingleResponse that answers `expected`, among the entries that
 * match on (normalized) serial and — when provided — `issuerKeyHashHex`.
 * `issuerNameHash` is NEVER part of this decision (RDN re-encoding variance
 * makes it useless once keyHash+serial already agree).
 *
 * Multiple matches: a `revoked` verdict wins (fail-closed on status) over any
 * `good`/`unknown` among the same matches; absent a `revoked` entry, the
 * freshest `thisUpdate` wins.
 */
function selectMatchingResponse(
  views: SingleResponseView[],
  expected: ExpectedCertId,
): SingleResponseView | null {
  const wantSerial = normalizeSerialHex(expected.serialHex);
  const wantKeyHash = expected.issuerKeyHashHex?.toLowerCase();

  const matches = views.filter((v) => {
    if (normalizeSerialHex(v.serialHex) !== wantSerial) return false;
    if (wantKeyHash !== undefined && v.issuerKeyHashHex.toLowerCase() !== wantKeyHash) return false;
    return true;
  });
  if (matches.length === 0) return null;

  const revoked = matches.filter((v) => v.certStatus === 'revoked');
  const pool = revoked.length > 0 ? revoked : matches;
  return pool.reduce((newest, v) => (v.thisUpdate > newest.thisUpdate ? v : newest));
}

/** Parse the nonce extension (OID 1.3.6.1.5.5.7.48.1.2), tolerating both the
 * doubly-wrapped OCTET STRING RFC 6960 §4.4.1 specifies and a bare payload. */
function extractResponseNonce(basic: pkijs.BasicOCSPResponse): Uint8Array | null {
  const exts = basic.tbsResponseData.responseExtensions ?? [];
  for (const ext of exts) {
    if (ext.extnID !== OID_OCSP_NONCE) continue;
    const outer = ext.extnValue.valueBlock.valueHexView;
    const outerU8 = outer instanceof Uint8Array ? outer : new Uint8Array(outer);
    const inner = asn1js.fromBER(toAB(outerU8));
    if (inner.offset !== -1 && inner.result instanceof asn1js.OctetString) {
      return new Uint8Array(inner.result.valueBlock.valueHexView);
    }
    // Tolerate a responder that skips the extra OCTET STRING envelope.
    return outerU8;
  }
  return null;
}

/**
 * Parse + verify an OCSP response (DER bytes).
 *
 * @param der raw DER bytes of OCSPResponse (NOT BasicOCSPResponse).
 * @param issuerCert issuing CA — trust anchor for the responder's chain, and
 *                   the direct verifier when the issuer signs without a
 *                   delegate.
 * @param expected the CertID the caller is asking about (RFC 6960 §4.2.1)
 *                   — see the module-level SECURITY note for why this is
 *                   mandatory rather than optional.
 *
 * @throws {OcspParseError} with `code: 'no_matching_single_response'` when
 *   the response is authenticated (`signatureValid` would be true) but NONE
 *   of its SingleResponse entries answer `expected` — the anti-replay guard.
 *   When the signature itself is invalid, no such throw happens (the caller
 *   must reject on `signatureValid` regardless of which entry is reported —
 *   evaluating a CertID from unauthenticated data buys nothing).
 */
export async function parseOcspResponse(
  der: Uint8Array,
  issuerCert: ParsedCert,
  expected: ExpectedCertId,
): Promise<ParsedOcspResponse> {
  const asn = asn1js.fromBER(toAB(der));
  if (asn.offset === -1) throw new OcspParseError('OCSPResponse ASN.1 decode failed');
  const ocspResp = new pkijs.OCSPResponse({ schema: asn.result });

  const status = ocspResp.responseStatus.valueBlock.valueDec;
  if (status !== 0) {
    throw new OcspParseError(`OCSP responseStatus = ${status}`);
  }
  const respBytes = ocspResp.responseBytes;
  if (!respBytes) throw new OcspParseError('OCSP responseBytes missing');
  if (respBytes.responseType !== OID_BASIC_OCSP_RESPONSE) {
    throw new OcspParseError(`unexpected responseType ${respBytes.responseType}`);
  }

  const innerHex = (respBytes.response.valueBlock as { valueHex: ArrayBuffer }).valueHex;
  const basicAsn = asn1js.fromBER(innerHex);
  if (basicAsn.offset === -1) throw new OcspParseError('BasicOCSPResponse decode failed');
  const basic = new pkijs.BasicOCSPResponse({ schema: basicAsn.result });

  if (basic.tbsResponseData.responses.length === 0) {
    throw new OcspParseError('no SingleResponse');
  }
  const views = basic.tbsResponseData.responses.map(viewSingleResponse);

  const issuerPki = pkijsCertFromDer(issuerCert.der);
  const { signatureValid, signatureDetail, responderPkiCert } = await resolveSigner(
    basic,
    issuerPki,
  );

  // The CertID match is only meaningful once the data is authenticated —
  // see the SECURITY note above. When the signature is invalid we still
  // return a best-effort entry (any match, else the first) so the shape is
  // always sane; the caller is required to gate on `signatureValid` first.
  const matched = selectMatchingResponse(views, expected);
  if (matched === null && signatureValid) {
    throw new OcspParseError(
      'OCSP response has no SingleResponse for the requested cert',
      undefined,
      DETAIL_NO_MATCH,
    );
  }
  const selected = matched ?? views[0]!;

  const producedAt = basic.tbsResponseData.producedAt as Date;
  const responderCert = responderPkiCert ? parsedCertFromPkijs(responderPkiCert) : null;
  const responderHasOcspSigningEku = responderPkiCert ? hasOcspSigningEku(responderPkiCert) : false;
  const responseNonce = extractResponseNonce(basic);

  const result: ParsedOcspResponse = {
    certIdHex: selected.issuerNameHashHex + selected.issuerKeyHashHex + selected.serialHex,
    issuerNameHashHex: selected.issuerNameHashHex,
    issuerKeyHashHex: selected.issuerKeyHashHex,
    serialHex: selected.serialHex,
    certIdHashAlgo: selected.certIdHashAlgo,
    certStatus: selected.certStatus,
    producedAt,
    thisUpdate: selected.thisUpdate,
    signatureValid,
    responderCert,
    responderHasOcspSigningEku,
    responseNonce,
  };
  if (selected.nextUpdate !== undefined) result.nextUpdate = selected.nextUpdate;
  if (selected.revokedAt !== undefined) result.revokedAt = selected.revokedAt;
  if (selected.revocationReason !== undefined) result.revocationReason = selected.revocationReason;
  if (signatureDetail !== undefined) result.signatureDetail = signatureDetail;
  return result;
}
