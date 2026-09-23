import {
  OcspParseError,
  type ParsedOcspResponse,
  parseOcspResponse,
} from '@firma-ec/ltv-validation';
import { OCSPRequest } from 'pkijs';
import type { Certificate } from 'pkijs';
import { issuerKeyHashByAlgo, ocspMatchesCert, serialHexOf, toLtvParsedCert } from './ltv';
import type { OcspStatus } from './result';

const OCSP_PROXY_BASE = 'https://ocsp.firmar.ec';
/** Tolerated clock skew between the responder and this device. */
const OCSP_CLOCK_SKEW_MS = 5 * 60 * 1000;
/**
 * Oldest `thisUpdate` accepted when the responder gives no `nextUpdate`
 * (RFC 6960 §3.2: it must be "sufficiently recent"). Without a bound, a
 * replayed response from before a revocation would read `good` forever.
 */
const OCSP_MAX_AGE_WITHOUT_NEXT_UPDATE_MS = 7 * 24 * 60 * 60 * 1000;

/** Build an OCSPRequest for `subjectCert` issued by `issuerCert` using the pkijs createForCertificate API. */
async function buildRequest(
  subjectCert: Certificate,
  issuerCert: Certificate,
): Promise<Uint8Array> {
  const req = new OCSPRequest();
  await req.createForCertificate(subjectCert, {
    issuerCertificate: issuerCert,
    hashAlgorithm: 'SHA-1',
  });
  return new Uint8Array(req.toSchema(true).toBER(false));
}

/** Send an OCSP request via the firmar.ec CF Worker proxy. */
async function postViaProxy(
  slug: string,
  reqBytes: Uint8Array,
  signal?: AbortSignal,
): Promise<Uint8Array> {
  const url = `${OCSP_PROXY_BASE}/${slug}`;
  const body = reqBytes.buffer.slice(
    reqBytes.byteOffset,
    reqBytes.byteOffset + reqBytes.byteLength,
  ) as ArrayBuffer;
  const init: RequestInit = {
    method: 'POST',
    headers: { 'Content-Type': 'application/ocsp-request' },
    body,
  };
  // exactOptionalPropertyTypes: signal must be null not undefined when absent
  if (signal !== undefined) init.signal = signal;
  const resp = await fetch(url, init);
  if (!resp.ok) throw new Error(`OCSP proxy ${slug} returned ${resp.status}`);
  const ab = await resp.arrayBuffer();
  return new Uint8Array(ab);
}

export interface OcspContext {
  signerCert: Certificate;
  issuerCert: Certificate;
  /** ARCOTEL slug to find the right responder via the proxy */
  acSlug: string;
}

export async function checkOcsp(
  ctx: OcspContext,
  opts: { fetchTimeoutMs?: number } = {},
): Promise<OcspStatus> {
  const checkedAt = new Date().toISOString();
  const timeoutMs = opts.fetchTimeoutMs ?? 6000;
  try {
    const reqBytes = await buildRequest(ctx.signerCert, ctx.issuerCert);
    const ac = new AbortController();
    // v0.7.31 — Hard deadline via Promise.race. AbortController alone is NOT
    // sufficient: on some mobile networks (observed on Android Chrome
    // 2026-05-20) a fetch stuck in DNS/TLS connection setup does not reject
    // when `ac.abort()` fires, so `await postViaProxy(...)` never settles and
    // the whole verification hangs (the worker posts no further progress and
    // only the bus.ts watchdog eventually trips at 30s). Racing the fetch
    // against a timer that REJECTS guarantees checkOcsp settles within
    // `timeoutMs` regardless of the underlying fetch's behaviour. We still call
    // ac.abort() to free the socket where the browser honours it.
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<never>((_, rej) => {
      timer = setTimeout(() => {
        ac.abort();
        rej(new Error(`OCSP timed out after ${timeoutMs}ms`));
      }, timeoutMs);
    });
    let respBytes: Uint8Array;
    try {
      respBytes = await Promise.race([postViaProxy(ctx.acSlug, reqBytes, ac.signal), deadline]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
    // Authenticated parse: responder signature (issuer or delegated with
    // id-kp-OCSPSigning) and a SingleResponse whose CertID answers THIS cert.
    // The previous parser read `responses[0]` unverified, so a response for
    // another cert, stale or tampered, was taken at face value.
    let parsed: ParsedOcspResponse;
    try {
      parsed = await parseOcspResponse(respBytes, toLtvParsedCert(ctx.issuerCert), {
        serialHex: serialHexOf(ctx.signerCert),
        issuerKeyHashByAlgo: await issuerKeyHashByAlgo(ctx.issuerCert),
      });
    } catch (e) {
      if (e instanceof OcspParseError) {
        return { status: 'unknown', checkedAt, source: 'live', reason: 'ocsp_response_unusable' };
      }
      throw e;
    }
    if (!parsed.signatureValid) {
      return {
        status: 'unknown',
        checkedAt,
        source: 'live',
        reason: 'ocsp_signature_not_verified',
      };
    }
    // The serial alone is not the cert: the CertID must also name its issuer.
    if (!(await ocspMatchesCert(parsed, ctx.signerCert, ctx.issuerCert))) {
      return { status: 'unknown', checkedAt, source: 'live', reason: 'ocsp_response_unusable' };
    }
    const now = Date.now();
    const stale =
      parsed.nextUpdate !== undefined
        ? parsed.nextUpdate.getTime() < now
        : parsed.thisUpdate.getTime() < now - OCSP_MAX_AGE_WITHOUT_NEXT_UPDATE_MS;
    const notYetValid = parsed.thisUpdate.getTime() > now + OCSP_CLOCK_SKEW_MS;
    if (stale || notYetValid) {
      return { status: 'unknown', checkedAt, source: 'live', reason: 'ocsp_response_not_current' };
    }
    const ocspResult: OcspStatus = { status: parsed.certStatus, checkedAt, source: 'live' };
    if (parsed.revokedAt !== undefined) ocspResult.revokedAt = parsed.revokedAt.toISOString();
    if (parsed.revocationReason !== undefined) ocspResult.reason = parsed.revocationReason;
    return ocspResult;
  } catch (e) {
    return {
      status: 'not_checked',
      checkedAt,
      source: 'none',
      reason: `OCSP fetch failed: ${(e as Error).message}`,
    };
  }
}
