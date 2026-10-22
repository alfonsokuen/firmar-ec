/**
 * @firma-ec/signer — PAdES-B-B signing for browser PWAs.
 *
 * F3 scaffolding (Tasks 1-3). Implementation lands in Tasks 4+.
 *
 * @see docs/superpowers/specs/2026-05-09-firma-ec-F3-firma-MVP-design.md
 */

import { SignerError } from './errors.js';
import type { SignOptions, SignResult } from './types.js';

export { SignerError, revokedError } from './errors.js';
export type { SignErrorCode } from './errors.js';
export { parsePfx } from './p12.js';
export { signPdfPades, ltvNotApplicable } from './pades.js';
export type { PadesSignOptions, PadesSignResult } from './pades.js';
export { collectLtvData, extractSignatureContents } from './ltv.js';
export type { CollectLtvOpts, CollectLtvResult } from './ltv.js';
// Re-exported so consumers (e.g. the PWA's batch-signing session worker) can
// build a per-session OCSP/CRL cache and pass it via LtvOpts.ocspCache /
// LtvOpts.crlCache without taking a direct dependency on
// @firma-ec/ltv-validation themselves.
export { createOcspCache, createCrlCache } from '@firma-ec/ltv-validation';
export type { OcspCache, CrlCache } from '@firma-ec/ltv-validation';
export { addIncrementalSignature } from './incrementalUpdate.js';
export { VERIFY_QR_BASE, buildVerifyQrUrl } from './verifyUrl.js';
export { buildQrPayload, subjectDnFromDer, formatIsoWithOffset } from './qrPayload.js';
export {
  attachVisibleSignatureAppearance,
  buildAppearanceOperators,
  embedHelvetica,
  truncateCN,
  validateVisibleSig,
  DEFAULT_VISIBLE_SIG_WIDTH,
  DEFAULT_VISIBLE_SIG_HEIGHT,
  MIN_VISIBLE_SIG_WIDTH,
  MIN_VISIBLE_SIG_HEIGHT,
} from './visibleSig.js';
export type { VisibleSigInput } from './visibleSig.js';
export { readPageGeometry, normalizeRotate } from './pageGeometry.js';
export type { PageGeometry } from './pageGeometry.js';
export {
  computeAutoPlacement,
  toCanonicalRect,
  DEFAULT_SIG_BOX_W,
  DEFAULT_SIG_BOX_H,
} from './autoPlacement.js';
export type {
  AnchorPlacementHint,
  AnchorPlacementKind,
  AutoPlacement,
  EmptySigField,
  ExistingSigRect,
  PlacementSurvey,
} from './autoPlacement.js';
export { classifyPlacement } from './placementConfidence.js';
export type {
  AnchorClassificationContext,
  ClassifyPlacementOpts,
  ConfidenceLevel,
  ConfidenceReason,
  PlacementConfidence,
} from './placementConfidence.js';
// FASE 3 — ancla de texto: dónde dice el propio documento que hay que firmar.
// `fontDecode`/`fontResources` siguen sin salir del barrel a propósito (nota
// original); `anchorMatch`/`anchorPlacement` SÍ salen porque son la interfaz
// pública que consume `apps/pwa` para pasarle `anchorSpec` a
// `analyzePdfForPlacement` y `anchor` a `computeAutoPlacement`.
export { compileAnchorMatcher } from './anchorMatch.js';
export type { AnchorHit, AnchorKind, AnchorMatcherSpec } from './anchorMatch.js';
export { computeAnchorPlacement } from './anchorPlacement.js';
export type { AnchorChoice, AnchorSignal } from './anchorPlacement.js';
// Entrada de análisis para consumidores SIN pdf-lib (la PWA): bytes → datos
// planos. Es lo que permite que `apps/pwa` calcule la colocación automática
// sin añadir pdf-lib a sus dependencias.
export { analyzePdfForPlacement } from './analyzePdf.js';
export { type TextBand, type TextBandsResult, readTextBands } from './textBands.js';
export type { AnalyzePdfForPlacementOpts, AnchorScan, PdfPlacementAnalysis } from './analyzePdf.js';
export { detectSignatures } from './detectExistingSignatures.js';
export type { ExistingSignature } from './detectExistingSignatures.js';
export { importPrivateKey, signWithKey, hashOf } from './webcrypto.js';
export { buildCmsSignedData } from './cms.js';
export type { BuildCmsOpts, BuildCmsResult } from './cms.js';
export type {
  LtvMeta,
  LtvOpts,
  LtvProfile,
  ParsedPfx,
  SigAlg,
  SignerCert,
  SignOptions,
  SignResult,
  TimestampMeta,
  VisibleSigSpec,
} from './types.js';

/**
 * Sign a PDF with PAdES-B-B (CAdES detached, /Adobe.PPKLite).
 *
 * **Not implemented yet** — placeholder for F3 Tasks 4+.
 */
export async function signPdf(_opts: SignOptions): Promise<SignResult> {
  throw new SignerError('unknown', '@firma-ec/signer: signPdf not implemented (F3 Task 4+)');
}
