/**
 * PAdES-B-B PDF signing for @firma-ec/signer.
 *
 * Pipeline:
 *   1. Load PDF with pdf-lib.
 *   2. Insert /Sig dict + ByteRange placeholder via @signpdf/placeholder-pdf-lib
 *      (`pdflibAddPlaceholder`). This writes a PDF where /Contents is a hex
 *      OCTET STRING of `signatureLength` bytes (all zeros) and /ByteRange is
 *      filled with `**********`.
 *   3. Save the PDF and locate the ByteRange + /Contents window.
 *   4. Build coveredBytes = pdfBytes with /Contents zeroed (the placeholder is
 *      already zeros, so this is just `[0..a+b) ‖ [c..c+d)`).
 *   5. Hash coveredBytes with the SigAlg's hash → messageDigest.
 *   6. Build CMS SignedData (detached) over messageDigest → cmsDer.
 *   7. Hex-encode cmsDer, pad to `signatureLength * 2` chars with '0', and
 *      write into the /Contents hex window.
 *
 * Reason / Location are written to the PDF Sig dict (/Reason, /Location) via
 * `pdflibAddPlaceholder`'s named params — they are NOT added to CMS signedAttrs
 * (Decision: PAdES B-B keeps signedAttrs minimal; reason/location belong to
 *  the visible-by-Reader Sig dict — see plan F3 Task 7).
 *
 * @see docs/superpowers/specs/2026-05-09-firma-ec-F3-firma-MVP-design.md §4.3
 */

import { appendDocumentTimestamp, appendDss } from '@firma-ec/dss-pdf';
import type { TimestampResult } from '@firma-ec/tsa-client';
import type { TrustIntermediate } from '@firma-ec/tsl-ec';
import { pdflibAddPlaceholder } from '@signpdf/placeholder-pdf-lib';
import { PDFArray, PDFDict, PDFDocument, PDFName } from 'pdf-lib';
import {
  type ResolveSigningIntermediatesAiaOpts,
  resolveSigningIntermediates,
} from './chainIntermediates.js';
import { buildCmsSignedData } from './cms.js';
import { SignerError, isEncryptedPdfError, revokedError } from './errors.js';
import { collectLtvData, extractSignatureContents } from './ltv.js';
import { fitQrPayload, subjectDnFromDer } from './qrPayload.js';
import type {
  LtvMeta,
  LtvOpts,
  LtvProfile,
  ParsedPfx,
  SigAlg,
  SignerCert,
  TimestampMeta,
} from './types.js';
import { buildVerifyQrUrl } from './verifyUrl.js';
import {
  type VisibleSigInput,
  __internals,
  attachVisibleSignatureAppearance,
  embedHelvetica,
  validateVisibleSig,
} from './visibleSig.js';
import { hashOf, importPrivateKey } from './webcrypto.js';

const SUBFILTER_ETSI_CADES_DETACHED = 'ETSI.CAdES.detached';
const DEFAULT_SIGNATURE_LENGTH = 32768;

/**
 * Smallest timeout worth spending a round trip on when an aggregate LTV deadline
 * is in force. Mirrors `ltv.ts`'s MIN_LEG_TIMEOUT_MS: under this a request can't
 * even complete a TLS handshake on a mobile network, so issuing it only burns
 * what is left of the caller's per-document budget.
 */
const MIN_DEADLINE_LEG_MS = 250;

/**
 * `perRequestMs` clamped to the time left before `deadlineAt`; `null` when there
 * is not enough left to be worth a request. No deadline ⇒ unchanged value
 * (previous behaviour).
 */
function clampToDeadline(perRequestMs: number, deadlineAt: number | undefined): number | null {
  if (deadlineAt === undefined) return perRequestMs;
  const left = deadlineAt - Date.now();
  if (left < MIN_DEADLINE_LEG_MS) return null;
  return Math.min(perRequestMs, left);
}

export interface PadesSignOptions {
  /** Override the SigAlg suite (default: parsedPfx.sigAlg). */
  sigAlg?: SigAlg;
  /** Reason to write into the /Sig dict (PDF level, NOT CMS). */
  reason?: string;
  /** Location to write into the /Sig dict (PDF level, NOT CMS). */
  location?: string;
  /** Contact info (PDF level). */
  contactInfo?: string;
  /** Signing time (default: `new Date()`). */
  signingTime?: Date;
  /** Signature length to reserve in /Contents (bytes; default 32768). */
  signatureLength?: number;
  /** Visible-signature widget rect [x1,y1,x2,y2] (default: hidden).
   *  Low-level escape hatch — prefer {@link visibleSig}. */
  widgetRect?: [number, number, number, number];
  /**
   * Visible signature placement. When provided, a Widget annotation rendering
   * "Firmado por: <CN>" is drawn on `page` at `[x, y, width, height]`. The
   * rectangle is validated against page bounds and minimum dimensions, with
   * Helvetica embedded as the appearance font. When omitted, the signature
   * is invisible (a 0×0 widget at origin) — caller-side preview unchanged.
   */
  visibleSig?: VisibleSigInput;
  /**
   * If true (default), request an RFC 3161 timestamp and embed it as a CMS
   * unsignedAttribute → PAdES B-T. If false, skip TSA and emit plain B-B.
   * F6 §Task 10.
   */
  timestamp?: boolean;
  /** Override TSA URL (default https://freetsa.org/tsr). */
  tsaUrl?: string;
  /** Override TSA fetch timeout in ms (default 8000). F6 §Task 15. */
  tsaTimeoutMs?: number;
  /**
   * Optional callback fired with the raw TimestampResult (or { error: 'disabled' })
   * after the TSA exchange completes — before CMS DER assembly. Lets the PWA
   * worker emit a 'request_timestamp' progress event mid-sign without having
   * to thread state through cms.ts. F6 §Task 10 / 14.
   */
  onTimestampResult?: (r: TimestampResult | { error: 'disabled' }) => void;
  /**
   * F7 — long-term validation options. When omitted (default), the signer
   * attempts both B-LT (DSS append) and B-LTA (document timestamp) after the
   * B-T step. Failures degrade the output to the highest successful tier.
   */
  ltv?: LtvOpts;
  /**
   * Override the subordinate-CA bundle used to embed a missing intermediate
   * when the .p12 ships leaf-only (default: the @firma-ec/tsl-ec set). Lets the
   * produced PDF be self-contained so offline verifiers can build the chain.
   */
  intermediateBundle?: TrustIntermediate[];
  /**
   * F1 — AIA `caIssuers` fallback for when `intermediateBundle` doesn't have
   * the missing intermediate. Enabled by default (ARCOTEL_PROXY_MAP, 5s
   * timeout). Pass `null` to disable entirely and keep the pre-F1 no-network
   * behaviour. See `chainIntermediates.ts` / `@firma-ec/ltv-validation`'s
   * `aia-certs.ts` for the trust boundary — this can only HELP complete a
   * chain toward an already-trusted root, never grant trust on its own.
   */
  aiaFallback?: ResolveSigningIntermediatesAiaOpts | null;
  /**
   * F1 — fired once with the outcome of the intermediate-chain resolution
   * (bundle + AIA fallback). Non-fatal: the signature completes either way.
   * Lets a caller (e.g. the PWA worker) surface a soft "couldn't confirm the
   * full trust chain" notice without gating the download.
   */
  onChainResolution?: (r: { complete: boolean; missingIssuerDn?: string }) => void;
}

/** Result of {@link signPdfPades} — F6 added timestamp; F7 added ltv. */
export interface PadesSignResult {
  /** Signed PDF bytes (drop-in for the original `Promise<Uint8Array>` return). */
  signedPdf: Uint8Array;
  /** Outcome of the RFC 3161 timestamp step (always present). */
  timestamp: TimestampMeta;
  /** F7 — outcome of the LT/LTA stages (always present). */
  ltv: LtvMeta;
  /**
   * F1 — true iff the intermediate chain embedded in the CMS reaches a
   * self-signed root (bundle and/or AIA fallback supplied every missing
   * link). Informational only — never used for trust decisions, and never
   * blocks the signature from completing. See `missingIssuerDn`.
   */
  chainComplete: boolean;
  /** Set when `chainComplete` is false: DN of the issuer that could not be
   *  resolved from the bundle nor via AIA. */
  missingIssuerDn?: string;
}

/** Extended ParsedPfx (includes PKCS#8 DER from p12.ts). */
type ParsedPfxFull = ParsedPfx & { privateKeyPkcs8Der: ArrayBuffer };

/**
 * Sign a PDF with PAdES-B-B.
 *
 * @returns The signed PDF bytes.
 */
export async function signPdfPades(
  pdfBytes: Uint8Array,
  parsedPfx: ParsedPfxFull,
  opts: PadesSignOptions = {},
): Promise<PadesSignResult> {
  const sigAlg = opts.sigAlg ?? parsedPfx.sigAlg;
  const signatureLength = opts.signatureLength ?? DEFAULT_SIGNATURE_LENGTH;
  const signingTime = opts.signingTime ?? new Date();

  // 1. Load PDF + insert placeholder
  let pdfDoc: PDFDocument;
  try {
    pdfDoc = await PDFDocument.load(pdfBytes);
  } catch (cause) {
    // A6 — un PDF cifrado SIEMPRE falla aquí, y salía como `bad_pdf` genérico.
    // Con código propio el llamante puede apartarlo en vez de contarlo como
    // documento roto. El análisis previo del lote ya lo detecta antes de
    // llegar hasta aquí; esto cubre a quien llame al firmante directamente.
    if (isEncryptedPdfError(cause)) {
      throw new SignerError(
        'pdf_encrypted',
        'El PDF está cifrado y no puede firmarse: hay que quitarle la protección primero.',
        cause,
      );
    }
    throw new SignerError(
      'bad_pdf',
      `pdf-lib failed to load PDF: ${cause instanceof Error ? cause.message : String(cause)}`,
      cause,
    );
  }

  // Validate visible-sig BEFORE placeholder insertion so we fail fast and
  // don't leave a partially-placeholder'd doc behind.
  if (opts.visibleSig) {
    validateVisibleSig(pdfDoc, opts.visibleSig);
  }

  // If caller asked for a visible signature, embed Helvetica up-front so the
  // font dict gets a stable indirect ref before we mutate the AP stream.
  let helvFontRef: Awaited<ReturnType<typeof embedHelvetica>> | undefined;
  if (opts.visibleSig) {
    helvFontRef = await embedHelvetica(pdfDoc);
  }

  // Compute widgetRect for pdflibAddPlaceholder. When visibleSig is given we
  // pass the same rect so the underlying widget annotation has a non-zero
  // /Rect from the start; we then post-process AP/N to render the appearance.
  const computedWidgetRect: [number, number, number, number] | undefined = opts.visibleSig
    ? [
        opts.visibleSig.x,
        opts.visibleSig.y,
        opts.visibleSig.x + opts.visibleSig.width,
        opts.visibleSig.y + opts.visibleSig.height,
      ]
    : opts.widgetRect;

  try {
    pdflibAddPlaceholder({
      pdfDoc,
      reason: opts.reason ?? 'Firma electronica',
      contactInfo: opts.contactInfo ?? '',
      name: parsedPfx.signingCert.subjectCN,
      location: opts.location ?? '',
      signingTime,
      signatureLength,
      subFilter: SUBFILTER_ETSI_CADES_DETACHED,
      ...(computedWidgetRect ? { widgetRect: computedWidgetRect } : {}),
    });
  } catch (cause) {
    throw new SignerError(
      'cms_build_failed',
      `Placeholder insertion failed: ${cause instanceof Error ? cause.message : String(cause)}`,
      cause,
    );
  }

  // Post-process: render the visible appearance on the just-created widget.
  // Note: pdflibAddPlaceholder appends the widget to page 0 by default. When
  // the caller targets a different page, the widget still lives on page 0;
  // we relocate it here by removing it from page 0's /Annots and pushing
  // onto the target page's /Annots before rewriting AP.
  if (opts.visibleSig && helvFontRef) {
    relocateLastWidgetIfNeeded(pdfDoc, opts.visibleSig.page);

    // v0.4.5 — Compute QR URL hint (sha256-12chars of original PDF bytes).
    // Using the *unsigned* source PDF gives us a stable, content-addressable
    // hint that survives re-signing (good for "find this document" UX) and
    // doesn't depend on placeholder bytes that vary per-sign.
    const hashBuf = await crypto.subtle.digest(
      'SHA-256',
      pdfBytes.buffer.slice(
        pdfBytes.byteOffset,
        pdfBytes.byteOffset + pdfBytes.byteLength,
      ) as ArrayBuffer,
    );
    const hashHex = Array.from(new Uint8Array(hashBuf))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
      .slice(0, 12);
    // F6.3 — QR encodes the PWA URL (app.firmar.ec) directly so scanners land
    // on the SPA hash route. Older signed PDFs (F3–F6.2) used the apex
    // (firmar.ec) which the landing now redirects via inline script.
    const qrUrl = buildVerifyQrUrl(hashHex);
    // El QR lleva el texto con quién firmó, el DN del certificado y la fecha
    // (como el QR de Security Data/FirmaEC); el enlace de verificación va dentro.
    const qrPayload = fitQrPayload(
      {
        signerName: parsedPfx.signingCert.subjectCN,
        subjectDn: subjectDnFromDer(parsedPfx.signingCert.der),
        verifyUrl: qrUrl,
        signingTime,
      },
      __internals.QR_AREA_PT,
    );

    attachVisibleSignatureAppearance(
      pdfDoc,
      {
        ...opts.visibleSig,
        qrUrl,
        qrPayload,
        signingTime,
        reason: opts.reason,
      },
      helvFontRef,
    );
  }

  // 2. Save PDF with placeholder
  let withPlaceholder: Uint8Array;
  try {
    withPlaceholder = await pdfDoc.save({ useObjectStreams: false });
  } catch (cause) {
    throw new SignerError(
      'bad_pdf',
      `pdf-lib save failed: ${cause instanceof Error ? cause.message : String(cause)}`,
      cause,
    );
  }

  // 3. Locate ByteRange + /Contents hex window
  const window = locateSignatureWindow(withPlaceholder);

  // 4. Build coveredBytes (placeholder /Contents is already zeros, so we just
  //    concatenate [0..a+b) ‖ [c..c+d) per /ByteRange).
  const [a, b, c, d] = window.byteRange;
  const covered = new Uint8Array(b + d);
  covered.set(withPlaceholder.subarray(a, a + b), 0);
  covered.set(withPlaceholder.subarray(c, c + d), b);

  // 5. Hash coveredBytes
  const hashAlg = hashOf(sigAlg);
  const messageDigest = new Uint8Array(
    await crypto.subtle.digest(
      hashAlg,
      covered.buffer.slice(
        covered.byteOffset,
        covered.byteOffset + covered.byteLength,
      ) as ArrayBuffer,
    ),
  );

  // 6. Import private key + build CMS (with optional RFC 3161 timestamp).
  // F7: capture the raw TSA cert via onTimestampResult so the LTV stage can
  // check its revocation status (the TSA cert is part of the trust chain
  // that needs DSS coverage).
  let capturedTsaCert: SignerCert | undefined;
  const privateKey = await importPrivateKey(parsedPfx.privateKeyPkcs8Der, sigAlg);
  const chainResolution = await resolveSigningIntermediates(
    parsedPfx.signingCert.der,
    parsedPfx.intermediates.map((c) => c.der),
    opts.intermediateBundle,
    opts.aiaFallback,
  );
  const intermediateCertDers = chainResolution.ders;
  opts.onChainResolution?.({
    complete: chainResolution.complete,
    ...(chainResolution.missingIssuerDn !== undefined
      ? { missingIssuerDn: chainResolution.missingIssuerDn }
      : {}),
  });
  const cmsResult = await buildCmsSignedData({
    messageDigest,
    signerCertDer: parsedPfx.signingCert.der,
    intermediateCertDers,
    privateKey,
    sigAlg,
    signingTime,
    ...(opts.timestamp !== undefined ? { timestamp: opts.timestamp } : {}),
    ...(opts.tsaUrl ? { tsaUrl: opts.tsaUrl } : {}),
    ...(opts.tsaTimeoutMs !== undefined ? { tsaTimeoutMs: opts.tsaTimeoutMs } : {}),
    onTimestampResult: (r) => {
      if ('token' in r && r.tsaCert) {
        capturedTsaCert = {
          subjectCN: r.tsaCert.subjectCN ?? '',
          issuerCN: r.tsaCert.issuerCN ?? '',
          der: r.tsaCert.der,
          notBefore: r.tsaCert.notBefore,
          notAfter: r.tsaCert.notAfter,
          serialHex: '',
        };
      }
      opts.onTimestampResult?.(r);
    },
  });
  const cmsDer = cmsResult.cms;
  const timestampMeta = cmsResult.timestamp;

  // 7. Hex-encode + pad + write into /Contents.
  // The placeholder reserved a hex string of `signatureLength` characters
  // (each char = one nibble — see @signpdf/placeholder-pdf-lib internals
  // where placeholder = hex of `String.fromCharCode(0).repeat(signatureLength)`,
  // i.e. `signatureLength*2` hex chars). We discover the real reserved
  // window size from the located range to be robust.
  const cmsHex = bytesToHex(cmsDer);
  const reservedHexLen = window.contentsHexEnd - window.contentsHexStart;
  if (cmsHex.length > reservedHexLen) {
    throw new SignerError(
      'signature_too_long',
      `CMS DER (${cmsDer.length} bytes, ${cmsHex.length} hex chars) exceeds reserved /Contents window (${reservedHexLen} hex chars). Increase signatureLength.`,
    );
  }
  const padded = cmsHex.padEnd(reservedHexLen, '0');

  // Write padded hex into the /Contents window
  const out = new Uint8Array(withPlaceholder);
  const enc = new TextEncoder();
  const hexBytes = enc.encode(padded);
  out.set(hexBytes, window.contentsHexStart);

  // 8. F7 — Long-term validation (LT / LTA).
  let signedPdf: Uint8Array = out;
  const ltvMeta: LtvMeta = {
    profile: timestampMeta.ok ? 'B-T' : 'B-B',
    longTermAchieved: false,
    archiveAchieved: false,
    embeddedOcspCount: 0,
    embeddedCrlCount: 0,
    warnings: [],
  };
  const ltvOpts = opts.ltv;
  const wantLt = ltvOpts?.longTerm !== false;
  const wantLta = ltvOpts?.longTermArchive !== false;

  if (wantLt) {
    try {
      const sigContents = extractSignatureContents(signedPdf);
      if (!sigContents) {
        ltvMeta.warnings.push({
          code: 'ltv_signature_contents_not_found',
          detail: 'extractSignatureContents returned null',
        });
      } else {
        const collected = await collectLtvData({
          signerCert: parsedPfx.signingCert,
          intermediates: parsedPfx.intermediates,
          tsaCert: capturedTsaCert,
          signatureContents: sigContents,
          timeoutMs: ltvOpts?.ocspTimeoutMs ?? 8000,
          ...(ltvOpts?.deadlineAt !== undefined ? { deadlineAt: ltvOpts.deadlineAt } : {}),
          ...(ltvOpts?.ocspUrl ? { ocspUrl: ltvOpts.ocspUrl } : {}),
          ...(ltvOpts?.crlUrl ? { crlUrl: ltvOpts.crlUrl } : {}),
          ...(ltvOpts?.ocspCache ? { ocspCache: ltvOpts.ocspCache } : {}),
          ...(ltvOpts?.crlCache ? { crlCache: ltvOpts.crlCache } : {}),
        });
        ltvMeta.warnings.push(...collected.warnings);
        if (collected.revoked) {
          throw revokedError(collected.revoked.cn);
        }
        if (collected.data.ocsps.length > 0 || collected.data.crls.length > 0) {
          signedPdf = await appendDss({ pdfBytes: signedPdf, dss: collected.data });
          ltvMeta.profile = 'B-LT';
          ltvMeta.longTermAchieved = true;
          ltvMeta.embeddedOcspCount = collected.data.ocsps.length;
          ltvMeta.embeddedCrlCount = collected.data.crls.length;
        } else {
          ltvMeta.warnings.push({ code: 'ltv_no_revocation_data' });
        }
      }
    } catch (e) {
      // Re-throw revoked (fatal). Other errors degrade to B-T.
      if (e instanceof SignerError && e.code === 'certificate_revoked') throw e;
      ltvMeta.warnings.push({
        code: 'ltv_unexpected_error',
        detail: e instanceof Error ? e.message : String(e),
      });
    }
  }

  const docTsTimeoutMs = clampToDeadline(ltvOpts?.ltvTimeoutMs ?? 8000, ltvOpts?.deadlineAt);
  if (ltvMeta.longTermAchieved && wantLta && docTsTimeoutMs === null) {
    // The aggregate LTV budget is spent. Skipping is the whole point of the
    // deadline — but it degrades the profile, so it is recorded, never silent.
    ltvMeta.warnings.push({
      code: 'lta_deadline_exceeded',
      detail: 'no time left in the LTV budget for the document timestamp',
    });
  } else if (ltvMeta.longTermAchieved && wantLta && docTsTimeoutMs !== null) {
    try {
      const dts = await appendDocumentTimestamp({
        pdfBytes: signedPdf,
        ...((ltvOpts?.documentTsaUrl ?? opts.tsaUrl)
          ? { tsaUrl: ltvOpts?.documentTsaUrl ?? opts.tsaUrl! }
          : {}),
        timeoutMs: docTsTimeoutMs,
      });
      if (dts.ok) {
        signedPdf = dts.pdfBytes;
        ltvMeta.profile = 'B-LTA';
        ltvMeta.archiveAchieved = true;
        ltvMeta.documentTimestampTime = dts.signingTime;
        ltvMeta.documentTimestampTsaIssuer = dts.tsaIssuerCN;
      } else {
        ltvMeta.warnings.push({
          code: `lta_doc_ts_${dts.reason}`,
          ...(dts.detail !== undefined ? { detail: dts.detail } : {}),
        });
      }
    } catch (e) {
      ltvMeta.warnings.push({
        code: 'lta_unexpected_error',
        detail: e instanceof Error ? e.message : String(e),
      });
    }
  }

  ltvOpts?.onLtvResult?.(ltvMeta);

  return {
    signedPdf,
    timestamp: timestampMeta,
    ltv: ltvMeta,
    chainComplete: chainResolution.complete,
    ...(chainResolution.missingIssuerDn !== undefined
      ? { missingIssuerDn: chainResolution.missingIssuerDn }
      : {}),
  };
}

/**
 * F7 — return a static LtvMeta indicating the LT/LTA pipeline did not run.
 * Used by the incremental update path (multi-firma) where LT only makes sense
 * for the outermost B-T signature.
 */
function ltvNotApplicable(profile: LtvProfile): LtvMeta {
  return {
    profile,
    longTermAchieved: false,
    archiveAchieved: false,
    embeddedOcspCount: 0,
    embeddedCrlCount: 0,
    warnings: [{ code: 'ltv_skipped_multifirma' }],
  };
}

export { ltvNotApplicable };

/** Result of locating the signature window in the placeholdered PDF. */
interface SigWindow {
  byteRange: [number, number, number, number];
  /** Offset in the PDF of the first hex digit inside `<...>` of /Contents. */
  contentsHexStart: number;
  /** Offset of the closing `>` of /Contents. */
  contentsHexEnd: number;
}

function locateSignatureWindow(pdf: Uint8Array): SigWindow {
  const text = new TextDecoder('latin1').decode(pdf);

  // /ByteRange may still hold the `**********` placeholder when @signpdf
  // hands the PDF back. We need to compute the real ByteRange ourselves
  // from the /Contents <...> hex window, then rewrite /ByteRange in place.
  // Strategy:
  //   1. Locate the /Contents hex window (always real bytes — < and >).
  //   2. Compute byteRange = [0, ltOffset+1−1, gtOffset, fileSize − gtOffset].
  //      i.e. byteRange = [0, ltOffset, gtOffset+1, fileSize-(gtOffset+1)].
  //   3. Replace the /ByteRange placeholder string with real numbers, padded
  //      with spaces so the file size doesn't change.
  const brStart = text.indexOf('/ByteRange');
  if (brStart < 0)
    throw new SignerError('cms_build_failed', '/ByteRange entry missing in placeholdered PDF');
  const brOpenBracket = text.indexOf('[', brStart);
  const brCloseBracket = text.indexOf(']', brOpenBracket);
  if (brOpenBracket < 0 || brCloseBracket < 0)
    throw new SignerError('cms_build_failed', '/ByteRange brackets missing');

  // Locate /Contents <...>
  const ctStart = text.indexOf('/Contents', brCloseBracket);
  if (ctStart < 0) throw new SignerError('cms_build_failed', '/Contents entry missing');
  let i = ctStart + '/Contents'.length;
  while (
    i < pdf.length &&
    (pdf[i] === 0x20 || pdf[i] === 0x09 || pdf[i] === 0x0a || pdf[i] === 0x0d)
  )
    i++;
  if (pdf[i] !== 0x3c)
    throw new SignerError(
      'cms_build_failed',
      `Expected '<' at /Contents start, got 0x${(pdf[i] ?? 0).toString(16)}`,
    );
  const ltOffset = i;
  let j = i + 1;
  while (j < pdf.length && pdf[j] !== 0x3e) j++;
  if (j >= pdf.length) throw new SignerError('cms_build_failed', '/Contents closing > not found');
  const gtOffset = j; // index of '>'

  // Compute real ByteRange:
  //   first slice: [0 .. ltOffset)         length = ltOffset
  //   second slice: [gtOffset+1 .. EOF)    length = pdf.length - (gtOffset + 1)
  const byteRange: [number, number, number, number] = [
    0,
    ltOffset,
    gtOffset + 1,
    pdf.length - (gtOffset + 1),
  ];

  // Rewrite /ByteRange in place with real numbers, preserving the original
  // bracket-to-bracket length so all offsets stay valid.
  const realStr = `[ ${byteRange[0]} ${byteRange[1]} ${byteRange[2]} ${byteRange[3]} ]`;
  const slotLen = brCloseBracket - brOpenBracket + 1;
  if (realStr.length > slotLen) {
    throw new SignerError(
      'cms_build_failed',
      `Real ByteRange string (${realStr.length}) exceeds reserved slot (${slotLen})`,
    );
  }
  const padded = realStr.padEnd(slotLen, ' ');
  const enc = new TextEncoder();
  const replacement = enc.encode(padded);
  pdf.set(replacement, brOpenBracket);

  return {
    byteRange,
    contentsHexStart: ltOffset + 1,
    contentsHexEnd: gtOffset,
  };
}

/**
 * `pdflibAddPlaceholder` always appends the widget to the FIRST page. When
 * the caller targets a different page, we move the widget annotation ref
 * across `/Annots` arrays here. The Sig field linkage (/V, /T, AcroForm
 * Fields) is by reference and survives the relocation.
 */
function relocateLastWidgetIfNeeded(pdfDoc: PDFDocument, targetPageIndex: number): void {
  if (targetPageIndex === 0) return;
  const pages = pdfDoc.getPages();
  const sourcePage = pages[0]!;
  const targetPage = pages[targetPageIndex];
  if (!targetPage) return; // already validated upstream, defensive

  const srcAnnots = sourcePage.node.lookupMaybe(PDFName.of('Annots'), PDFArray);
  if (!srcAnnots || srcAnnots.size() === 0) return;
  const lastIdx = srcAnnots.size() - 1;
  const lastRef = srcAnnots.get(lastIdx);
  // Remove from source. PDFArray exposes .remove(idx) in recent versions; if
  // not, rebuild without the last entry.
  const ctx = pdfDoc.context;
  const newSrc = PDFArray.withContext(ctx);
  for (let i = 0; i < srcAnnots.size() - 1; i++) newSrc.push(srcAnnots.get(i));
  sourcePage.node.set(PDFName.of('Annots'), newSrc);

  // Append to target.
  let dstAnnots = targetPage.node.lookupMaybe(PDFName.of('Annots'), PDFArray);
  if (!dstAnnots) {
    dstAnnots = PDFArray.withContext(ctx);
  }
  dstAnnots.push(lastRef);
  targetPage.node.set(PDFName.of('Annots'), dstAnnots);

  // Also update the widget's /P (page ref) to match.
  const widgetObj = ctx.lookup(lastRef);
  if (widgetObj instanceof PDFDict) {
    widgetObj.set(PDFName.of('P'), targetPage.ref);
  }
}

function bytesToHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i]!.toString(16).padStart(2, '0');
  return s;
}
