/**
 * Visible signature widget builder for @firma-ec/signer.
 *
 * Sprint C Batch 5 — F3 Tasks 17-19.
 *
 * Design (per UI Pro Max adendum 2026-05-09):
 *   - Single template: only "Firmado por: <CN>" (no date / reason / location
 *     in the visible box — those still land in the /Sig dict for Reader).
 *   - No border (MVP).
 *   - Helvetica (PDF standard font, embedded as a resource named /Helv).
 *   - Default 200×60 pt, but user-controllable via x/y/width/height.
 *   - 6pt internal padding, black text, transparent background.
 *
 * The actual widget annotation + Sig dict are created by
 * `@signpdf/placeholder-pdf-lib`'s `pdflibAddPlaceholder`, which produces an
 * empty Form XObject as the widget Appearance Stream. Our job here:
 *
 *   1. **Validate** the requested rect against the target page bounds and
 *      minimum dimensions.
 *   2. **Embed** Helvetica via `pdfDoc.embedFont(StandardFonts.Helvetica)` so
 *      we have a reusable font ref.
 *   3. After the placeholder is inserted, **locate** the Widget annotation
 *      added to the target page (it's the last `/Subtype /Widget` annot on
 *      the page) and **rewrite** its `AP/N` Form XObject:
 *        - set BBox to the rect's local-space [0, 0, w, h],
 *        - attach `Resources << /Font << /Helv <fontRef> >> >>`,
 *        - replace the empty operator list with the "Firmado por: …" draw.
 *
 * The widget remains linked to the Sig dict via `/V`, so signing semantics
 * are unchanged — we only paint the appearance.
 *
 * @see docs/superpowers/specs/2026-05-09-firma-ec-F3-firma-MVP-design.md §4.4
 */

import { stripIdPrefix } from '@firma-ec/crypto-core';
import {
  PDFArray,
  PDFContentStream,
  PDFDict,
  type PDFDocument,
  PDFHexString,
  PDFName,
  type PDFOperator,
  PDFRef,
  StandardFonts,
  beginText,
  endText,
  fill,
  moveText,
  popGraphicsState,
  pushGraphicsState,
  rectangle,
  setFillingRgbColor,
  setFontAndSize,
  showText,
} from 'pdf-lib';
import QRCode from 'qrcode';
import { SignerError } from './errors.js';
import { createQrLink } from './qrLink.js';
import { toWinAnsiHex as toWinAnsiHexString, widthOfText } from './textFit.js';

/** Public input for a visible signature placement (Batch 5 contract). */
export interface VisibleSigInput {
  /** 0-based page index. */
  page: number;
  /** Lower-left X in PDF user-space (origin bottom-left). */
  x: number;
  /** Lower-left Y in PDF user-space. */
  y: number;
  /** Box width in pt. */
  width: number;
  /** Box height in pt. */
  height: number;
  /** Signer common name to render — typically `parsedPfx.signingCert.subjectCN`. */
  signerCN: string;
  /**
   * The signer's cédula. NOT the certificate's own serial number. Rendered as
   * a "Cédula: …" line when present; omitting it has no effect on the layout
   * (byte-identical to before this field existed). Sourced from
   * `parsedPfx.signingCert.holderCedula`, which resolves it from the issuing
   * ACE's private OID arc — see `ecCertIdentity`.
   */
  signerId?: string | undefined;
  /**
   * v0.4.5 — Optional URL to encode into a QR code rendered on the left of the
   * widget (FirmaEC-style). When provided, the widget switches to split layout:
   * 60×60pt QR on the left + 3-line text block on the right. When omitted,
   * legacy single-line layout is used (back-compat with v0.4.4 tests).
   */
  qrUrl?: string | undefined;
  /** v0.4.5 — Signing time used for L2 "Fecha:" line. Defaults to `new Date()`. */
  signingTime?: Date | undefined;
  /** v0.4.5 — Reason rendered in L3. Defaults to "firmar.ec". */
  reason?: string | undefined;
  /**
   * Posicionamiento automático (lotes) — grados de `/Rotate` de la PÁGINA
   * destino (PDF 32000-1 §7.7.3.3, no de la apariencia). Default `0`:
   * comportamiento idéntico byte a byte al de antes de este campo.
   *
   * Cuando `rotate !== 0`, la apariencia se dibuja en su orientación natural
   * (BBox sin rotar) y se rota con `/Matrix` para que se vea derecha en el
   * visor pese a que la página está rotada — ver la tabla de
   * `packages/signer/src/autoPlacement.ts` (spec §2) para la derivación de
   * qué `/Matrix` corresponde a cada `/Rotate`. `x/y/width/height` siguen
   * siendo el rect FÍSICO (el que ocupa `/Rect` en la página ya rotada) —
   * con `rotate` 90/270 eso es h×w del cuadro "en lectura", no w×h.
   */
  rotate?: 0 | 90 | 180 | 270 | undefined;
}

/** Default rectangle suggested by UX pass when user hasn't placed it yet. */
export const DEFAULT_VISIBLE_SIG_WIDTH = 200;
export const DEFAULT_VISIBLE_SIG_HEIGHT = 60;
/** v0.4.5 — Default size when QR is enabled (FirmaEC-style 240×72). */
export const DEFAULT_VISIBLE_SIG_QR_WIDTH = 240;
export const DEFAULT_VISIBLE_SIG_QR_HEIGHT = 72;

/** Minimum legible box (smaller than this and Helv 10pt with 6pt padding clips). */
export const MIN_VISIBLE_SIG_WIDTH = 30;
export const MIN_VISIBLE_SIG_HEIGHT = 30;

/** Internal padding (pt) inside the widget box. */
const PADDING_PT = 6;

/** Helvetica font size (pt). */
const FONT_SIZE_PT = 10;

/** Maximum CN characters before truncation with ellipsis. */
const MAX_CN_CHARS = 50;
const ELLIPSIS = '…'; // single-char ellipsis (WinAnsi 0x85, valid in Helvetica)

/** "Firmado por: " label prefix. */
const LABEL = 'Firmado por: ';
/** Prefijo de la 3ª línea, medido para recortar la razón por ancho. */
const REASON_LABEL = 'Razón: ';
/** Etiqueta de la línea de cédula/identificación del firmante. */
const CEDULA_LABEL = 'Cédula: ';
/**
 * Líneas fijas del bloque de texto que NO son el nombre (fecha + razón).
 * El nombre aporta 1 línea normalmente, 2 cuando no cabe a lo ancho; la
 * cédula aporta 1 línea adicional solo cuando `signerId` viene informado.
 */
const OTHER_LINE_COUNT = 2;

// v0.4.5 — Split-layout constants (FirmaEC-style, 240×72pt total).
/** QR cell + inside margin. The QR sits in a 60×60 box at offset (PADDING_PT, PADDING_PT). */
const QR_AREA_PT = 60;

/**
 * Ancho (pt) por debajo del cual la estampa no enseña NI UN dato del firmante.
 *
 * El bloque de texto arranca en un x FIJO (`PADDING_PT + QR_AREA_PT +
 * PADDING_PT`, ver el render mas abajo) y el BBox del XObject es
 * `[0, 0, width, height]`, o sea que RECORTA. Con un ancho por debajo de esta
 * cota, "Firmado por", la cedula y la fecha caen enteros fuera del BBox y lo
 * unico que queda visible es un QR mordido: una estampa muda sobre una firma
 * con PKCS#7, TSA y OCSP ya gastados.
 *
 * No es lo mismo que {@link MIN_VISIBLE_SIG_WIDTH}, que es el minimo del
 * VALIDADOR (que el rect no sea degenerado). Un rect de 40 pt pasa la
 * validacion y aun asi no dice quien firmo. Quien estreche una caja de firma
 * tiene que respetar ESTA, no aquella.
 */
export const MIN_LEGIBLE_SIG_WIDTH = PADDING_PT + QR_AREA_PT + PADDING_PT + PADDING_PT;
/** Small font for the 3-line right block. */
const SMALL_FONT_SIZE_PT = 8;
/** CN max for the split-layout L1 (fits within ~174pt − padding @ 8pt Helvetica). */
const SPLIT_MAX_CN_CHARS = 35;

/**
 * Validate that a {@link VisibleSigInput} fits in the target page and meets
 * minimum legibility constraints.
 *
 * Throws {@link SignerError} with one of:
 *   - `visible_sig_invalid_page` — page index < 0 or ≥ pageCount.
 *   - `visible_sig_too_small`    — width < 30 or height < 30.
 *   - `visible_sig_out_of_bounds` — rect extends outside page MediaBox.
 */
export function validateVisibleSig(pdfDoc: PDFDocument, spec: VisibleSigInput): void {
  const pages = pdfDoc.getPages();
  if (!Number.isInteger(spec.page) || spec.page < 0 || spec.page >= pages.length) {
    throw new SignerError(
      'visible_sig_invalid_page',
      `Visible signature page index ${spec.page} out of range [0..${pages.length - 1}]`,
    );
  }
  // `NaN` es el ÚNICO valor que aprueba todas las comprobaciones de más abajo,
  // porque toda comparación con él da `false`. Sin esta guarda positiva, un rect
  // salido de una geometría no finita pasaba la compuerta FINAL de firma y se
  // estampaba un widget con coordenadas basura, contado como éxito limpio entre
  // sus 49 hermanos del lote. Un `<` nunca puede ser la única defensa contra NaN.
  if (
    !Number.isFinite(spec.x) ||
    !Number.isFinite(spec.y) ||
    !Number.isFinite(spec.width) ||
    !Number.isFinite(spec.height)
  ) {
    throw new SignerError(
      'visible_sig_not_finite',
      `Visible signature rect has non-finite coordinates on page ${spec.page}`,
    );
  }
  if (spec.width < MIN_VISIBLE_SIG_WIDTH || spec.height < MIN_VISIBLE_SIG_HEIGHT) {
    throw new SignerError(
      'visible_sig_too_small',
      `Visible signature box ${spec.width}×${spec.height} pt below minimum ${MIN_VISIBLE_SIG_WIDTH}×${MIN_VISIBLE_SIG_HEIGHT}`,
    );
  }
  const page = pages[spec.page]!;
  const { width: pageW, height: pageH } = page.getSize();
  if (spec.x < 0 || spec.y < 0 || spec.x + spec.width > pageW || spec.y + spec.height > pageH) {
    throw new SignerError(
      'visible_sig_out_of_bounds',
      `Visible signature rect [${spec.x},${spec.y} ${spec.width}×${spec.height}] does not fit page ${spec.page} (${pageW}×${pageH})`,
    );
  }
}

/** Truncate a CN to at most {@link MAX_CN_CHARS} including ellipsis. */
export function truncateCN(cn: string, maxChars: number = MAX_CN_CHARS): string {
  if (cn.length <= maxChars) return cn;
  return cn.slice(0, maxChars - 1) + ELLIPSIS;
}

/**
 * Encode a string into a PDF hex literal targeting Helvetica's WinAnsi encoding.
 * Used for `Tj` operands. La tabla y el saneado viven en `textFit.ts`, que
 * es lo que usa también la ruta de multifirma: una sola forma de escribir.
 */
function toWinAnsiHex(text: string): PDFHexString {
  return PDFHexString.of(toWinAnsiHexString(text));
}

/**
 * Métricas reales de Helvetica sin necesitar un `PDFDocument`: mide el ancho
 * de la cadena en puntos en vez de contar caracteres. Contar caracteres es lo
 * que hacía `truncateCN`, y por eso fallaba — una 'W' ocupa casi el triple que
 * una 'i'. Mide lo saneado, que es lo que se dibuja, y nunca lanza: un nombre
 * con un carácter que Helvetica no tiene se dibuja con su sustituto en vez de
 * tumbar la firma con «code: unknown».
 */
export function measureHelvetica(text: string, sizePt: number): number {
  return widthOfText(text, sizePt);
}

/** Recorta `text` por ANCHO medido, dejando sitio para la elipsis. */
export function truncateToWidth(text: string, sizePt: number, maxWidthPt: number): string {
  if (measureHelvetica(text, sizePt) <= maxWidthPt) return text;
  let lo = 0;
  let hi = text.length;
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    if (measureHelvetica(text.slice(0, mid) + ELLIPSIS, sizePt) <= maxWidthPt) lo = mid;
    else hi = mid - 1;
  }
  return text.slice(0, lo) + ELLIPSIS;
}

/**
 * Reparte el CN en una o dos líneas según el ancho disponible.
 *
 * La primera línea comparte sitio con la etiqueta "Firmado por: ", así que
 * dispone de menos ancho que la segunda. Devuelve `[línea1, null]` cuando el
 * nombre cabe entero — el caso en que la estampa sale idéntica a la de antes.
 */
export function splitCNIntoLines(
  cn: string,
  sizePt: number,
  firstLineWidthPt: number,
  secondLineWidthPt: number,
): [string, string | null] {
  if (measureHelvetica(cn, sizePt) <= firstLineWidthPt) return [cn, null];

  const words = cn.split(/\s+/).filter((w) => w.length > 0);
  let first = '';
  let consumed = 0;
  for (; consumed < words.length; consumed++) {
    const candidate = first === '' ? words[consumed]! : `${first} ${words[consumed]!}`;
    if (measureHelvetica(candidate, sizePt) > firstLineWidthPt) break;
    first = candidate;
  }
  // Ni la primera palabra cabe (un apellido larguísimo sin espacios): no hay
  // reparto posible que ayude, se recorta por ancho en una sola línea.
  if (first === '') return [truncateToWidth(cn, sizePt, firstLineWidthPt), null];

  const rest = words.slice(consumed).join(' ');
  if (rest === '') return [first, null];
  return [first, truncateToWidth(rest, sizePt, secondLineWidthPt)];
}

/**
 * Format a Date as `YYYY-MM-DD HH:mm` in the local timezone of the signer.
 * Matches the FirmaEC desktop convention.
 */
export function formatSigningTime(d: Date): string {
  const pad = (n: number) => n.toString().padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/**
 * Generate a QR code matrix (size×size of 0/1) for `text` and return PDF
 * operators that paint the dark modules as filled rectangles inside a
 * `cellSizePt × cellSizePt` box anchored at local origin (0,0).
 *
 * Uses `qrcode`'s internal {@link QRCode.create} which returns a synchronous
 * BitMatrix — no DOM, no canvas, no network. 100% client-safe.
 */
export function buildQrOperators(text: string, cellSizePt: number): PDFOperator[] {
  // M-level error correction matches FirmaEC's tradeoff (~15% recovery).
  const qr = QRCode.create(text, { errorCorrectionLevel: 'M' });
  const size = qr.modules.size;
  const data = qr.modules.data; // Uint8Array, length = size*size, 1 = dark
  const moduleSize = cellSizePt / size;

  const ops: PDFOperator[] = [pushGraphicsState(), setFillingRgbColor(0, 0, 0)];
  // Coalesce horizontal runs of dark modules per row into a single rect to
  // shrink the operator list ~3-5x. Y is bottom-up (PDF user space), so row 0
  // of the matrix is the TOP of the QR — we flip it.
  for (let row = 0; row < size; row++) {
    let runStart = -1;
    for (let col = 0; col <= size; col++) {
      const dark = col < size && data[row * size + col] === 1;
      if (dark && runStart < 0) {
        runStart = col;
      } else if (!dark && runStart >= 0) {
        const x = runStart * moduleSize;
        const y = (size - 1 - row) * moduleSize;
        const w = (col - runStart) * moduleSize;
        const h = moduleSize;
        ops.push(rectangle(x, y, w, h));
        runStart = -1;
      }
    }
  }
  ops.push(fill());
  ops.push(popGraphicsState());
  return ops;
}

/**
 * Build the operator list that draws "Firmado por: <CN>" inside a box of the
 * given dimensions. The widget's BBox is `[0, 0, width, height]`, so all
 * coordinates are local.
 */
export function buildAppearanceOperators(
  width: number,
  height: number,
  signerCN: string,
  opts: {
    qrUrl?: string | undefined;
    signingTime?: Date | undefined;
    reason?: string | undefined;
    signerId?: string | undefined;
  } = {},
): PDFOperator[] {
  // ── v0.4.5 split layout (QR + 3-line text + outline) ────────────────────
  if (opts.qrUrl) {
    const ops: PDFOperator[] = [];

    // Sin marco/borde alrededor del BBox: la estampa (QR + texto) queda limpia
    // sobre el documento, sin recuadro (removido a pedido del usuario).

    // QR area: 60×60 anchored at (PADDING_PT, PADDING_PT) — bottom-left corner.
    // Internal margin: PADDING_PT all around. We translate by setting
    // origin via a `cm` matrix push — but pdf-lib lacks `concatTransformationMatrix`
    // helper... we shift coordinates manually inside buildQrOperators.
    // Simplest: render QR ops with offset by computing inline rects already
    // including the offset. Replay buildQrOperators output and shift each
    // rectangle's x,y by (PADDING_PT, PADDING_PT). Easier: emit a `q` + manual
    // translation via `1 0 0 1 tx ty cm`. pdf-lib expects PDFOperator; we use
    // PDFOperator.of(name, args) — see helpers. Since `cm` isn't exported as a
    // helper, we fall back to coordinate offsetting at the rectangle level.
    const qrOps = buildQrOperators(opts.qrUrl, QR_AREA_PT);
    // Offset every rectangle op by (PADDING_PT, PADDING_PT). PDFOperator name
    // for rectangle() is 're' with args [x, y, w, h] (PDFNumber objects).
    for (const op of qrOps) {
      // PDFOperator exposes `.name` (string like 're') and `.args` (PDFObject[]).
      const opAny = op as unknown as {
        name: string;
        args: ReadonlyArray<{ asNumber?: () => number; numberValue?: number }>;
      };
      if (opAny.name === 're') {
        const numAt = (i: number): number => {
          const a = opAny.args[i]!;
          return typeof a.asNumber === 'function' ? a.asNumber() : (a.numberValue ?? 0);
        };
        const x = numAt(0) + PADDING_PT;
        const y = numAt(1) + PADDING_PT;
        const w = numAt(2);
        const h = numAt(3);
        ops.push(rectangle(x, y, w, h));
      } else {
        ops.push(op);
      }
    }

    // Right-side text block: starts at x = PADDING_PT + QR_AREA_PT + PADDING_PT.
    const textStartX = PADDING_PT + QR_AREA_PT + PADDING_PT; // = 72 with PADDING_PT=6
    const textWidth = width - textStartX - PADDING_PT; // = 162 en la caja de 240
    const fecha = formatSigningTime(opts.signingTime ?? new Date());
    const reason = opts.reason && opts.reason.trim().length > 0 ? opts.reason.trim() : 'firmar.ec';

    // El nombre se reparte por ANCHO MEDIDO, no por número de caracteres. Un CN
    // ecuatoriano típico (dos nombres + dos apellidos) ronda los 32 caracteres y
    // no cabe detrás de la etiqueta, así que antes se recortaba mudo contra el
    // borde del BBox. La caja tiene 72 pt de alto y solo usaba 3 líneas de 10:
    // el sitio que falta a lo ancho sobra a lo alto.
    const lineGap = 10;
    const topBaseline = height - PADDING_PT - SMALL_FONT_SIZE_PT * 0.85;
    const maxLines = Math.max(1, Math.floor((topBaseline - PADDING_PT) / lineGap) + 1);

    const labelWidth = measureHelvetica(LABEL, SMALL_FONT_SIZE_PT);
    let [cnLine1, cnLine2] = splitCNIntoLines(
      signerCN,
      SMALL_FONT_SIZE_PT,
      textWidth - labelWidth,
      textWidth,
    );
    // Presupuesto de líneas fijas: fecha + razón, más la cédula SOLO si vino.
    // Sin signerId el cálculo es idéntico al de antes de este campo (byte a
    // byte), que es justo lo que el test "sin signerId no cambia" verifica.
    const fixedLineCount = OTHER_LINE_COUNT + (opts.signerId ? 1 : 0);
    // Una caja más baja de lo normal puede no tener sitio para la línea extra
    // del nombre; en ese caso se vuelve al recorte de una línea, por ancho.
    if (cnLine2 !== null && fixedLineCount + 2 > maxLines) {
      cnLine1 = truncateToWidth(signerCN, SMALL_FONT_SIZE_PT, textWidth - labelWidth);
      cnLine2 = null;
    }

    const lines = [
      `${LABEL}${cnLine1}`,
      ...(cnLine2 !== null ? [cnLine2] : []),
      ...(opts.signerId
        ? [
            `${CEDULA_LABEL}${truncateToWidth(
              stripIdPrefix(opts.signerId),
              SMALL_FONT_SIZE_PT,
              textWidth - measureHelvetica(CEDULA_LABEL, SMALL_FONT_SIZE_PT),
            )}`,
          ]
        : []),
      `Fecha: ${fecha}`,
      `Razón: ${truncateToWidth(reason, SMALL_FONT_SIZE_PT, textWidth - measureHelvetica(REASON_LABEL, SMALL_FONT_SIZE_PT))}`,
    ];

    ops.push(
      pushGraphicsState(),
      setFillingRgbColor(0, 0, 0),
      beginText(),
      setFontAndSize('Helv', SMALL_FONT_SIZE_PT),
      moveText(textStartX, topBaseline),
    );
    lines.forEach((line, i) => {
      if (i > 0) ops.push(moveText(0, -lineGap));
      ops.push(showText(toWinAnsiHex(line)));
    });
    ops.push(endText(), popGraphicsState());

    return ops;
  }

  // ── Legacy single-line layout (back-compat with v0.4.4 callers) ─────────
  void width;
  const text = LABEL + truncateCN(signerCN);

  // Single line baseline at top of the box minus padding minus font ascent.
  // Helvetica ascent ≈ 0.718 of em; for size 10 ≈ 7.18 pt. We use a simple
  // heuristic: place baseline at `height - PADDING - FONT_SIZE * 0.8`.
  const baselineY = Math.max(PADDING_PT, height - PADDING_PT - FONT_SIZE_PT * 0.8);

  return [
    pushGraphicsState(),
    setFillingRgbColor(0, 0, 0),
    beginText(),
    setFontAndSize('Helv', FONT_SIZE_PT),
    moveText(PADDING_PT, baselineY),
    showText(toWinAnsiHex(text)),
    endText(),
    popGraphicsState(),
  ];
}

/**
 * Find the Widget annotation that `pdflibAddPlaceholder` just appended to the
 * given page. It's the last Annot whose `/Subtype` is `Widget` AND whose
 * `/FT` is `Sig` (we ignore non-signature widgets like form fields).
 */
function findLastSigWidget(pdfDoc: PDFDocument, pageIndex: number): PDFDict {
  const page = pdfDoc.getPages()[pageIndex];
  if (!page) {
    throw new SignerError(
      'visible_sig_invalid_page',
      `Page ${pageIndex} not found while linking widget`,
    );
  }
  const annots = page.node.lookupMaybe(PDFName.of('Annots'), PDFArray);
  if (!annots) {
    throw new SignerError(
      'cms_build_failed',
      `Page ${pageIndex} has no /Annots after pdflibAddPlaceholder — placeholder did not register the widget`,
    );
  }
  // Walk backwards to grab the most recently appended sig widget.
  for (let i = annots.size() - 1; i >= 0; i--) {
    const item = annots.lookup(i);
    if (!(item instanceof PDFDict)) continue;
    const subtype = item.lookupMaybe(PDFName.of('Subtype'), PDFName);
    const ft = item.lookupMaybe(PDFName.of('FT'), PDFName);
    if (
      subtype &&
      ft &&
      // PDFName toString returns "/Widget" / "/Sig"
      subtype.toString() === '/Widget' &&
      ft.toString() === '/Sig'
    ) {
      return item;
    }
  }
  throw new SignerError(
    'cms_build_failed',
    `No /Subtype /Widget /FT /Sig annotation found on page ${pageIndex}`,
  );
}

/**
 * Replace the empty Appearance Stream that `pdflibAddPlaceholder` produced
 * with a real one rendering "Firmado por: <CN>".
 *
 * This function:
 *   1. Looks up the most recently added sig Widget annotation on `spec.page`.
 *   2. Rewrites its /Rect to the new rectangle (in case caller passed a
 *      different rect than the widgetRect plumbed through pdflibAddPlaceholder).
 *   3. Locates the AP/N Form XObject and:
 *        - sets BBox = [0, 0, width, height],
 *        - attaches `Resources << /Font << /Helv <helvFontRef> >> >>`,
 *        - replaces operators with {@link buildAppearanceOperators}.
 *
 * @returns The widget annotation dict (for caller introspection / tests).
 */
export function attachVisibleSignatureAppearance(
  pdfDoc: PDFDocument,
  spec: VisibleSigInput,
  helvFontRef: PDFRef,
): { widget: PDFDict; appearanceStream: PDFContentStream } {
  const widget = findLastSigWidget(pdfDoc, spec.page);

  // Rewrite /Rect to match the spec exactly (lower-left x,y → upper-right).
  const ctx = pdfDoc.context;
  const x1 = spec.x;
  const y1 = spec.y;
  const x2 = spec.x + spec.width;
  const y2 = spec.y + spec.height;
  widget.set(PDFName.of('Rect'), ctx.obj([x1, y1, x2, y2]));

  // Look up AP /N
  const ap = widget.lookupMaybe(PDFName.of('AP'), PDFDict);
  if (!ap) {
    throw new SignerError(
      'cms_build_failed',
      `Widget annotation missing /AP dict — pdflibAddPlaceholder contract changed`,
    );
  }
  const nRef = ap.get(PDFName.of('N'));
  if (!(nRef instanceof PDFRef)) {
    throw new SignerError(
      'cms_build_failed',
      `Widget /AP/N is not an indirect reference — got ${nRef?.constructor.name ?? 'undefined'}`,
    );
  }
  const apStream = ctx.lookup(nRef);
  if (!(apStream instanceof PDFContentStream)) {
    throw new SignerError(
      'cms_build_failed',
      `Widget /AP/N target is not a PDFContentStream — got ${apStream?.constructor.name ?? 'undefined'}`,
    );
  }

  // v0.9.0 — rotation support (batch auto-placement, spec §3.3). Default
  // `rotate = 0` keeps BBox/Matrix/operators byte-identical to before this
  // field existed. For 90/270 the PHYSICAL rect (spec.width/height, used for
  // /Rect above and for /BBox below) is h×w of the box "in reading order" —
  // the appearance itself is always drawn in its natural (unrotated)
  // orientation and /Matrix rotates it to match the page. See the
  // rotate→(swap, matrix) table derivation in autoPlacement.ts (spec §2).
  const rotate = spec.rotate ?? 0;
  const isSwapped = rotate === 90 || rotate === 270;
  const apWidth = isSwapped ? spec.height : spec.width;
  const apHeight = isSwapped ? spec.width : spec.height;
  // Rotación CCW de θ = [cosθ sinθ −sinθ cosθ 0 0] (PDF 32000-1 §8.3.4). El
  // visor calcula el bounding box de BBox transformado por Matrix y lo
  // reescala/traslada para llenar /Rect — con una rotación pura (sin escala)
  // eso resuelve el traslado solo, no hace falta meterlo en la matriz.
  const matrix: [number, number, number, number, number, number] =
    rotate === 90
      ? [0, -1, 1, 0, 0, 0] // apariencia gira -90° para verse derecha en una página /Rotate 90
      : rotate === 180
        ? [-1, 0, 0, -1, 0, 0]
        : rotate === 270
          ? [0, 1, -1, 0, 0, 0] // apariencia gira +90°
          : [1, 0, 0, 1, 0, 0];

  // Update the XObject dict: BBox + Resources + Subtype/Type guarantees.
  const apDict = apStream.dict;
  apDict.set(PDFName.of('Type'), PDFName.of('XObject'));
  apDict.set(PDFName.of('Subtype'), PDFName.of('Form'));
  apDict.set(PDFName.of('BBox'), ctx.obj([0, 0, apWidth, apHeight]));
  apDict.set(PDFName.of('Matrix'), ctx.obj(matrix));
  apDict.set(
    PDFName.of('Resources'),
    ctx.obj({
      Font: { Helv: helvFontRef },
    }),
  );

  // Replace operators in-place. v0.4.5 — pass qrUrl/signingTime/reason through
  // so split layout (QR + 3-line text + border) lands on the AP/N stream.
  // v0.9.0 — operators draw in the appearance's own (unrotated) BBox space,
  // so they use apWidth/apHeight, not the physical spec.width/height.
  const ops = buildAppearanceOperators(apWidth, apHeight, spec.signerCN, {
    qrUrl: spec.qrUrl,
    signingTime: spec.signingTime,
    reason: spec.reason,
    signerId: spec.signerId,
  });
  // PDFContentStream.operators is a public mutable array — see core/structures/PDFContentStream.js.
  (apStream as unknown as { operators: PDFOperator[] }).operators = ops;

  // Note: we don't override /T (field name); pdflibAddPlaceholder sets it to
  // 'Signature1' and the @signpdf incremental path expects that.

  // Add the link before ByteRange/CMS are calculated; the text area keeps
  // the signature widget's normal certificate-details interaction.
  if (spec.qrUrl) {
    const link = createQrLink(pdfDoc, spec, spec.qrUrl, [
      PADDING_PT,
      PADDING_PT,
      PADDING_PT + QR_AREA_PT,
      PADDING_PT + QR_AREA_PT,
    ]);
    pdfDoc.getPage(spec.page).node.addAnnot(ctx.register(link));
  }

  return { widget, appearanceStream: apStream };
}

/**
 * Convenience: embed Helvetica (a standard PDF font) into `pdfDoc` and return
 * its indirect reference for use in widget /Resources.
 *
 * Helvetica is one of the 14 PDF Type 1 standard fonts — viewers ship it,
 * so embedding adds only a font dictionary, not the font program.
 */
export async function embedHelvetica(pdfDoc: PDFDocument): Promise<PDFRef> {
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
  return font.ref;
}

/** Low-level export for tests / advanced callers. */
export const __internals = {
  truncateCN,
  buildAppearanceOperators,
  buildQrOperators,
  formatSigningTime,
  findLastSigWidget,
  PADDING_PT,
  FONT_SIZE_PT,
  SMALL_FONT_SIZE_PT,
  QR_AREA_PT,
  MAX_CN_CHARS,
  SPLIT_MAX_CN_CHARS,
  LABEL,
  CEDULA_LABEL,
};
