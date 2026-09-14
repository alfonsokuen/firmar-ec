/**
 * Incremental update path for multi-firma secuencial.
 *
 * Approach (manual, no pdf-lib `save()`):
 *   - Take `signedPdfBytes` AS-IS — its bytes [0..fileEnd) become slice 1 of
 *     the new signature's /ByteRange and remain byte-perfect, so the previous
 *     signature(s) `/ByteRange` still cover the exact same bytes and stay
 *     verifiable.
 *   - Parse the prior xref (last `startxref` → table or stream) to learn:
 *       - prev xref offset → goes into the new trailer's `/Prev`
 *       - `/Size` (highest in-use object number + 1)
 *       - `/Root` reference (so the new trailer carries the Catalog ref)
 *       - locations of Catalog, AcroForm (if any), and first Page object
 *   - Build a tail (appended to file) that contains:
 *       1. New Sig dict object — includes `/ByteRange [0 ******** ******** ********]`
 *          plus `/Contents <000…>` placeholder (signatureLength bytes hex).
 *       2. New Widget annotation (refers to the new Sig).
 *       3. New AcroForm appearance stream (empty Form XObject for PDF/A).
 *       4. Updated Catalog — the prior catalog dict is preserved verbatim and
 *          only the /AcroForm entry is replaced/inserted (v0.8.2 — a 3-key
 *          template here used to drop /StructTreeRoot, /Lang, /Metadata,
 *          /MarkInfo, /PageLayout, flagging the revision as a suspicious
 *          modification in strict validators).
 *       5. Updated AcroForm — prior dict preserved; /Fields gains the new
 *          widget ref (resolving an indirect /Fields array if needed) and
 *          /SigFlags is OR'd with 3.
 *       6. Page /Annots — literal array: the page is rewritten with the
 *          widget appended. Indirect array ref: the array OBJECT itself is
 *          redefined with the widget appended and the page is NOT touched
 *          (v0.8.2 — nesting the old array ref inside a new literal /Annots
 *          made viewers drop every prior widget: the "FirmaEC stamp
 *          disappears on second signature" bug).
 *       7. xref subsections covering the new + updated objects, with the
 *          "free" entries left untouched.
 *       8. Trailer with `/Size`, `/Prev <prevXref>`, `/Root <catalogRef>`.
 *       9. `startxref <newXrefOff>` + `%%EOF`.
 *   - Compute the real /ByteRange from the placeholdered tail position, write
 *     it into the placeholder slot, hash, build CMS, write hex /Contents.
 *
 * After this routine returns, calling `findSignature` (verifier) on the
 * output yields the LATEST signature; calling `detectSignatures` (this
 * package) yields all of them.
 *
 * --- Constraints ---
 *
 *   - Implementation does **NOT** rewrite any byte of the input. Slice 1 of
 *     the new signature is `[0, lengthOfInput)` — the previous signature's
 *     /ByteRange therefore still covers an unchanged byte sequence.
 *   - We require the input to be a non-encrypted, non-linearized PDF with a
 *     classic xref **table** (cross-ref streams are rejected with
 *     `cannot_add_signature_to_corrupt_pdf`). pdf-lib emits classic tables
 *     when `useObjectStreams: false`, which is what `signPdfPades` does.
 *   - First page is the host for the new widget annotation.
 *
 * @see plan F3 Task 10 / batch-4 Task 13.
 */

import { PDFArray, PDFDict, PDFDocument, PDFName, PDFNumber, PDFRef, PDFString } from 'pdf-lib';
import QRCode from 'qrcode';
import { resolveSigningIntermediates } from './chainIntermediates.js';
import { buildCmsSignedData } from './cms.js';
import { detectSignatures } from './detectExistingSignatures.js';
import { SignerError, isEncryptedPdfError } from './errors.js';
import type { PadesSignOptions } from './pades.js';
import { createQrLink } from './qrLink.js';
import { fitChars, toWinAnsiHex, truncateToWidth } from './textFit.js';
import type { ParsedPfx, SigAlg } from './types.js';
import { buildVerifyQrUrl } from './verifyUrl.js';
import { validateVisibleSig } from './visibleSig.js';
import { hashOf, importPrivateKey } from './webcrypto.js';

const SUBFILTER_ETSI_CADES_DETACHED = 'ETSI.CAdES.detached';
const DEFAULT_SIGNATURE_LENGTH = 32768;

/**
 * Topes de caracteres del bloque de texto de la estampa en la ruta incremental.
 * Son los que ya aplicaba el código; se conservan como primer recorte para no
 * cambiar la salida de las líneas que ya cabían (el ajuste por ancho de
 * `textFit.ts` actúa después). Ver defecto A5.
 */
const MAX_CN_CHARS_INCREMENTAL = 40;
const MAX_META_CHARS_INCREMENTAL = 50;

type ParsedPfxFull = ParsedPfx & { privateKeyPkcs8Der: ArrayBuffer };

/**
 * Add a new PAdES-B-B signature to an already-signed PDF via incremental update.
 *
 * Output bytes start with `signedPdfBytes` byte-for-byte; new objects + xref
 * + trailer + %%EOF are appended after.
 */
export async function addIncrementalSignature(
  signedPdfBytes: Uint8Array,
  parsedPfx: ParsedPfxFull,
  opts: PadesSignOptions = {},
): Promise<Uint8Array> {
  // --- Quick sanity: input must be a PDF with at least one signature ---
  if (signedPdfBytes.length < 100 || signedPdfBytes[0] !== 0x25 /* % */) {
    throw new SignerError(
      'cannot_add_signature_to_corrupt_pdf',
      'Input does not start with PDF header',
    );
  }

  let prior;
  try {
    prior = await detectSignatures(signedPdfBytes);
  } catch (cause) {
    throw new SignerError(
      'cannot_add_signature_to_corrupt_pdf',
      `Failed to enumerate prior signatures: ${cause instanceof Error ? cause.message : String(cause)}`,
      cause,
    );
  }
  if (prior.length === 0) {
    throw new SignerError(
      'incremental_update_failed',
      'addIncrementalSignature called on a PDF with zero existing signatures — use signPdfPades instead',
    );
  }

  const sigAlg: SigAlg = opts.sigAlg ?? parsedPfx.sigAlg;
  const signatureLength = opts.signatureLength ?? DEFAULT_SIGNATURE_LENGTH;
  const signingTime = opts.signingTime ?? new Date();

  // --- Load with pdf-lib FIRST: besides the sanity check, its parser
  //     decompresses object streams (/ObjStm), so it doubles as the fallback
  //     resolver for parsePriorPdf below (v0.15.4 — iText & friends compress
  //     the page tree; the raw-text scan alone can't see those objects). ---
  let stub: PDFDocument;
  try {
    stub = await PDFDocument.load(signedPdfBytes, { updateMetadata: false });
  } catch (cause) {
    // A6 — cifrado tiene código propio: no es un PDF corrupto, es uno que hay
    // que desproteger. Confundirlos manda a la persona a buscar daño donde no
    // lo hay.
    if (isEncryptedPdfError(cause)) {
      throw new SignerError(
        'pdf_encrypted',
        'El PDF está cifrado y no puede firmarse: hay que quitarle la protección primero.',
        cause,
      );
    }
    throw new SignerError(
      'cannot_add_signature_to_corrupt_pdf',
      `pdf-lib load failed: ${cause instanceof Error ? cause.message : String(cause)}`,
      cause,
    );
  }

  /**
   * Fallback body resolver for objects that live inside compressed object
   * streams (no top-level `N G obj` in the raw bytes). pdf-lib already parsed
   * the document, ObjStms included; `PDFDict.toString()` re-serializes the
   * dictionary in plain PDF syntax, which is exactly the "body text" shape
   * `readObjectBody` returns. Dict-only on purpose: the structural objects we
   * resolve (Catalog, Pages, Page, AcroForm) are all dictionaries.
   */
  const resolveCompressedBody = (objNum: number, genNum: number): string | null => {
    try {
      const obj = stub.context.lookup(PDFRef.of(objNum, genNum));
      if (obj instanceof PDFDict) return obj.toString();
      return null;
    } catch {
      return null;
    }
  };

  // --- Parse prior xref + structural refs we need to update ---
  let info: PriorPdfInfo;
  try {
    info = parsePriorPdf(signedPdfBytes, resolveCompressedBody);
  } catch (cause) {
    throw new SignerError(
      'cannot_add_signature_to_corrupt_pdf',
      `Failed to parse prior PDF structure: ${cause instanceof Error ? cause.message : String(cause)}`,
      cause,
    );
  }

  // We allocate fresh object numbers for the NEW objects (Sig, Widget,
  // FormXObject for /AP). Updates to existing objects (Catalog, AcroForm,
  // Page) reuse the same object number with generation bumped (we use
  // gen+1 — PDF spec doesn't strictly require it, but it's the conservative
  // value).
  let nextObjNum = info.size; // first free obj number
  const sigObjNum = nextObjNum++;
  const widgetObjNum = nextObjNum++;
  const apObjNum = nextObjNum++;
  let acroFormObjNum: number;
  let acroFormGenNum = 0;
  if (info.acroFormRef) {
    acroFormObjNum = info.acroFormRef.objectNumber;
    acroFormGenNum = info.acroFormRef.generationNumber;
  } else {
    acroFormObjNum = nextObjNum++;
  }

  // --- Build dictionary text fragments ---
  const reason = opts.reason ?? 'Firma electronica';
  const location = opts.location ?? '';
  const contactInfo = opts.contactInfo ?? '';
  const name = parsedPfx.signingCert.subjectCN;

  // Signature object — placeholder /ByteRange + /Contents zeros.
  // We pad /ByteRange placeholders generously so real numbers fit.
  const byteRangePlaceholder = '[ 0 **********0 **********0 **********0 ]';
  const contentsPlaceholderHex = '0'.repeat(signatureLength * 2);
  const sigObjText =
    `${sigObjNum} 0 obj\n` +
    `<<\n` +
    `/Type /Sig\n` +
    `/Filter /Adobe.PPKLite\n` +
    `/SubFilter /${SUBFILTER_ETSI_CADES_DETACHED}\n` +
    `/ByteRange ${byteRangePlaceholder}\n` +
    `/Contents <${contentsPlaceholderHex}>\n` +
    `/Reason ${pdfStringLiteral(reason)}\n` +
    `/Location ${pdfStringLiteral(location)}\n` +
    `/ContactInfo ${pdfStringLiteral(contactInfo)}\n` +
    `/Name ${pdfStringLiteral(name)}\n` +
    `/M ${pdfDateLiteral(signingTime)}\n` +
    `>>\n` +
    `endobj\n`;

  // v0.7.18 — Visible signature support in incremental path.
  // Resolve target page from opts.visibleSig.page (0-based). Sin `visibleSig`
  // la firma es invisible por diseño: primera página + /Rect [0 0 0 0].
  const vs = opts.visibleSig;
  // A1 — red de seguridad: si se PIDIÓ estampa visible y la página no se
  // resuelve, se falla explícitamente. Degradar a `/Rect [0 0 0 0]` producía
  // una firma invisible que el lote reportaba como `done`: el usuario recibía
  // N documentos "firmados" sin ninguna estampa a la vista, sin un solo aviso.
  if (vs && (!Number.isInteger(vs.page) || vs.page < 0 || vs.page >= info.pageRefs.length)) {
    throw new SignerError(
      'visible_sig_invalid_page',
      `Visible signature page index ${vs.page} out of range [0..${info.pageRefs.length - 1}] — refusing to write an invisible signature instead`,
    );
  }
  // QA post-merge 2026-08-03 (code-reviewer, OWASP A04/A08, reproducido
  // ejecutando ambas rutas con las mismas 4 entradas inválidas): a diferencia
  // de `signPdfPades` (`pades.ts`, llama `validateVisibleSig` antes de tocar
  // el PDF), esta ruta solo comprobaba el índice de página — un rect fuera de
  // la página, más chico que el mínimo legible, o con coordenadas NO FINITAS
  // se aceptaba y se escribía tal cual en `/Rect` (incluido `[NaN ... NaN ...]`,
  // sintaxis PDF inválida grabada en el archivo). Esta es precisamente la ruta
  // que toma TODO documento que ya trae una firma previa — el conjunto exacto
  // que el lote manda a colocación manual (`needs_review` con
  // `empty_field_conflicts_with_prior_signature`) — así que el rect que llega
  // aquí puede venir de una persona ajustando a mano en la UI, no solo del
  // motor. `stub` (cargado arriba con pdf-lib) ya resuelve el tamaño real de
  // cada página, `/MediaBox` heredado incluido, así que se reusa la MISMA
  // función de validación que la ruta de firma única, en vez de reimplementar
  // los mismos límites por segunda vez con el riesgo de que diverjan.
  if (vs) {
    validateVisibleSig(stub, vs);
  }
  const visible = vs !== undefined;
  const targetPageRef = visible ? info.pageRefs[vs!.page]! : info.firstPageRef;
  const targetPageBody = visible
    ? (readObjectBody(
        new TextDecoder('latin1').decode(signedPdfBytes),
        targetPageRef.objectNumber,
        targetPageRef.generationNumber,
      ) ??
      resolveCompressedBody(targetPageRef.objectNumber, targetPageRef.generationNumber) ??
      info.firstPageBody)
    : info.firstPageBody;
  const widgetRect = visible
    ? `[${vs!.x} ${vs!.y} ${vs!.x + vs!.width} ${vs!.y + vs!.height}]`
    : '[0 0 0 0]';
  // A3 — rotación de la página destino, con el MISMO tratamiento que la ruta
  // de firma única (`visibleSig.ts`): la apariencia se dibuja siempre en su
  // orientación natural y es `/Matrix` quien la gira, así que el BBox lleva las
  // dimensiones "en lectura" (intercambiadas respecto al rect FÍSICO cuando la
  // página está a 90/270). Antes se fijaba `[0 0 width height]` sin swap y sin
  // `/Matrix`: con `/Rotate 90` el BBox quedaba de 72 pt de ancho, el bloque de
  // texto arrancaba justo en su borde y se recortaba entero — quedaba solo el
  // QR, girado.
  const rotate = visible ? (vs!.rotate ?? 0) : 0;
  const isRotationSwapped = rotate === 90 || rotate === 270;
  const apWidth = visible ? (isRotationSwapped ? vs!.height : vs!.width) : 0;
  const apHeight = visible ? (isRotationSwapped ? vs!.width : vs!.height) : 0;
  const apBBox = visible ? `[0 0 ${apWidth} ${apHeight}]` : '[0 0 0 0]';
  // Rotación CCW de θ = [cosθ sinθ −sinθ cosθ 0 0] (PDF 32000-1 §8.3.4) —
  // misma tabla que `visibleSig.ts`. Con `rotate 0` no se emite `/Matrix` en
  // absoluto: la identidad es el default del formato y omitirla deja la salida
  // byte-idéntica a la de antes de este arreglo.
  const apMatrix =
    rotate === 90
      ? ' /Matrix [0 -1 1 0 0 0]'
      : rotate === 180
        ? ' /Matrix [-1 0 0 -1 0 0]'
        : rotate === 270
          ? ' /Matrix [0 1 -1 0 0 0]'
          : '';
  // Appearance stream: bordered box + QR (left) + multi-line text (right).
  // v0.7.20:
  //   - Texto se emite como hex strings <...> con bytes WinAnsi (Latin-1) en
  //     vez de literal `(...)` — antes "Razón" salía "RazÃ³n" porque la cadena
  //     UTF-8 se interpretaba como Latin-1 por el viewer.
  //   - QR a la izquierda (60×60 con padding) codificando la URL del verifier
  //     con los primeros 12 hex chars del SHA-256 del PDF de entrada — match
  //     con lo que hace signPdfPades para single-sig (pades.ts:212).
  let qrLinkPart: { objNum: number; genNum: number; text: string } | undefined;
  let apStreamBody: string;
  let apResources: string;
  if (visible) {
    // Espacio de la APARIENCIA (sin rotar) — no el rect físico: ver A3 arriba.
    const w = apWidth;
    const h = apHeight;
    const padding = 6;
    const qrAreaPt = Math.max(40, Math.min(h - 2 * padding, 60));
    // Compute QR URL — hash the input PDF (pre-sign) so it matches the
    // verifier UI's "h=" deep-link convention used by signPdfPades.
    const inputHashBuf = await crypto.subtle.digest(
      'SHA-256',
      signedPdfBytes.buffer.slice(
        signedPdfBytes.byteOffset,
        signedPdfBytes.byteOffset + signedPdfBytes.byteLength,
      ) as ArrayBuffer,
    );
    const hashHex = Array.from(new Uint8Array(inputHashBuf))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
      .slice(0, 12);
    const qrUrl = buildVerifyQrUrl(hashHex);

    const fontSize = 7;
    const lineGap = fontSize + 2;
    const textStartX = padding + qrAreaPt + padding;
    const textWidth = Math.max(40, w - textStartX - padding);

    // Encode helpers
    const pad2 = (n: number) => String(n).padStart(2, '0');
    const dt = signingTime;
    const fecha = `${dt.getFullYear()}-${pad2(dt.getMonth() + 1)}-${pad2(dt.getDate())} ${pad2(dt.getHours())}:${pad2(dt.getMinutes())}`;
    // A5 — cada línea se ajusta MIDIENDO contra `textWidth`, el hueco real que
    // deja el layout. El tope de caracteres se conserva delante (era lo único
    // que había) para que las líneas que ya cabían salgan idénticas; el
    // ajuste por ancho solo muerde donde antes el BBox recortaba en silencio.
    const fitLine = (label: string, value: string, maxValueChars: number) =>
      truncateToWidth(label + fitChars(value, maxValueChars), fontSize, textWidth);
    const lines: string[] = [
      fitLine('Firmado por: ', name, MAX_CN_CHARS_INCREMENTAL),
      fitLine('Fecha: ', fecha, MAX_META_CHARS_INCREMENTAL),
    ];
    if (reason) lines.push(fitLine('Razón: ', reason, MAX_META_CHARS_INCREMENTAL));
    if (location) lines.push(fitLine('Lugar: ', location, MAX_META_CHARS_INCREMENTAL));

    // Texto → hex WinAnsi con la tabla real y el saneado de `textFit.ts`,
    // los mismos que usa la firma única: lo que se mide es lo que se dibuja.

    // Build QR operators: each dark module → filled rect. Coalesce horizontal
    // runs per row into a single rect to shrink the op stream.
    const qr = QRCode.create(qrUrl, { errorCorrectionLevel: 'M' });
    const size = qr.modules.size;
    const data = qr.modules.data;
    const moduleSize = qrAreaPt / size;
    const qrX = padding; // QR origin = bottom-left corner of QR area inside BBox
    const qrY = h - padding - qrAreaPt;
    const linkObjNum = nextObjNum++;
    const link = createQrLink(stub, vs!, qrUrl, [qrX, qrY, qrX + qrAreaPt, qrY + qrAreaPt]);
    qrLinkPart = {
      objNum: linkObjNum,
      genNum: 0,
      text: `${linkObjNum} 0 obj\n${link.toString()}\nendobj\n`,
    };
    const qrOps: string[] = ['0 0 0 rg'];
    for (let row = 0; row < size; row++) {
      let runStart = -1;
      for (let col = 0; col <= size; col++) {
        const dark = col < size && data[row * size + col] === 1;
        if (dark && runStart < 0) {
          runStart = col;
        } else if (!dark && runStart >= 0) {
          const x = qrX + runStart * moduleSize;
          // PDF user space is bottom-up; matrix row 0 = top, so flip.
          const yLocal = qrY + (size - 1 - row) * moduleSize;
          const rw = (col - runStart) * moduleSize;
          qrOps.push(
            `${x.toFixed(3)} ${yLocal.toFixed(3)} ${rw.toFixed(3)} ${moduleSize.toFixed(3)} re`,
          );
          runStart = -1;
        }
      }
    }
    qrOps.push('f');

    // Text block — first line baseline near top of BBox.
    const topY = h - padding - fontSize;
    const txtOps: string[] = [
      '0 0 0 rg',
      'BT',
      `/Helv ${fontSize} Tf`,
      `${textStartX} ${topY} Td`,
      `<${toWinAnsiHex(lines[0]!)}> Tj`,
    ];
    for (let i = 1; i < lines.length; i++) {
      txtOps.push(`0 -${lineGap} Td`, `<${toWinAnsiHex(lines[i]!)}> Tj`);
    }
    txtOps.push('ET');

    const allOps: string[] = [
      'q',
      // Sin marco/borde: solo QR + texto (el recuadro gris se removió a
      // pedido — la estampa queda limpia sobre el documento).
      // QR painted in black
      ...qrOps,
      // Text block
      ...txtOps,
      'Q',
    ];
    apStreamBody = allOps.join('\n') + '\n';
    apResources = `/Resources << /Font << /Helv << /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >> >> >>`;
  } else {
    apStreamBody = `q\nQ\n`;
    apResources = `/Resources << >>`;
  }
  const apObjText =
    `${apObjNum} 0 obj\n` +
    `<< /Type /XObject /Subtype /Form /BBox ${apBBox}${apMatrix} ${apResources} /Length ${apStreamBody.length} >>\n` +
    `stream\n${apStreamBody}endstream\n` +
    `endobj\n`;

  // Widget annotation referencing the Sig (V) and the FormXObject (AP/N).
  //
  // 2026-05-15 (v0.7.17): scan ALL existing `/T (Signature<N>)` field names
  // in the input PDF and pick the first integer N that does NOT collide.
  // Previously we used `prior.length + 1`, which produced collisions on PDFs
  // whose existing fields jump indices (e.g. Adobe-produced PDFs label fields
  // `Signature`, `Signature3`, `Signature4`, `Signature5` — 4 sigs, counter
  // says 5, collides with the existing MARCO field. Result: PDF viewers
  // (incl. FirmaEC desktop) dedupe by name and drop one of the signatures.
  const inputText = new TextDecoder('latin1').decode(signedPdfBytes);
  const existingFieldNames = new Set<string>();
  for (const m of inputText.matchAll(/\/T\s*\(([^)]+)\)/g)) {
    existingFieldNames.add(m[1]!);
  }
  // Adobe (and any producer that compresses the AcroForm) stores field dicts
  // inside object streams, so the field's /T never appears in the raw text and
  // the scan above misses it. Enumerate via pdf-lib (already parsed, ObjStm-
  // aware) so the new field's /T can't collide with an existing one — a /T
  // collision makes viewers dedupe by name and silently drop a signature
  // (ISO 32000-1 §12.7.3.2: terminal field names must be unique). Real case:
  // Adobe-signed PDF whose only field is /T (Signature2), compressed.
  try {
    for (const field of stub.getForm().getFields()) {
      const name = field.getName();
      if (name) existingFieldNames.add(name);
    }
  } catch {
    // Best-effort: fall back to the raw-text scan if the form can't be read.
  }
  const fieldName = pickSignatureFieldName(existingFieldNames, prior.length);
  const widgetObjText =
    `${widgetObjNum} 0 obj\n` +
    `<<\n` +
    `/Type /Annot\n` +
    `/Subtype /Widget\n` +
    `/FT /Sig\n` +
    `/Rect ${widgetRect}\n` +
    `/V ${sigObjNum} 0 R\n` +
    `/T ${pdfStringLiteral(fieldName)}\n` +
    `/F 4\n` +
    `/P ${targetPageRef.objectNumber} ${targetPageRef.generationNumber} R\n` +
    `/AP << /N ${apObjNum} 0 R >>\n` +
    `>>\n` +
    `endobj\n`;

  /**
   * Resolve the INNER text (elements, no brackets) of an indirect array
   * object, e.g. `/Annots 28 0 R` → `46 0 R 155 0 R`. pdf-lib is consulted
   * first because it walks the xref chain to the LATEST revision (the raw
   * last-occurrence scan would miss updates living inside a later /ObjStm —
   * exactly how iText appends its signature widget). Raw scan is the
   * fallback for plain classical PDFs.
   */
  const resolveArrayInner = (objNum: number, genNum: number): string => {
    try {
      const obj = stub.context.lookup(PDFRef.of(objNum, genNum));
      if (obj instanceof PDFArray) {
        return obj
          .toString()
          .trim()
          .replace(/^\[\s*/, '')
          .replace(/\s*\]$/, '')
          .trim();
      }
    } catch {
      // fall through to raw scan
    }
    const rawBody = readObjectBody(inputText, objNum, genNum);
    if (rawBody) {
      const m = rawBody.match(/^\[([\s\S]*)\]$/);
      if (m) return m[1]!.trim();
    }
    throw new SignerError(
      'incremental_update_failed',
      `Could not resolve indirect array object ${objNum} ${genNum} R referenced by the page or AcroForm`,
    );
  };

  // Extra object redefinitions queued by the /Annots and /Fields handling
  // below (indirect-array cases redefine the array object itself).
  const extraParts: Array<{ objNum: number; genNum: number; text: string }> = [];

  // Updated AcroForm — v0.8.2: preserve the prior AcroForm dict verbatim
  // (e.g. /DA, /DR, /NeedAppearances); only /Fields gains the new widget ref
  // and /SigFlags is OR'd. SigFlags = SignaturesExist (1) | AppendOnly (2).
  let acroFormObjText: string;
  if (info.acroFormRef && info.acroFormBody) {
    let afBody = info.acroFormBody;
    const priorSigFlags = Number.parseInt(afBody.match(/\/SigFlags\s+(\d+)/)?.[1] ?? '0', 10);
    const newSigFlags = priorSigFlags | 3;
    const fieldsLiteral = afBody.match(/\/Fields\s*\[([^\]]*)\]/);
    if (fieldsLiteral) {
      const inner = fieldsLiteral[1]!.trim();
      afBody = afBody.replace(
        fieldsLiteral[0],
        `/Fields [${inner.length > 0 ? `${inner} ` : ''}${widgetObjNum} 0 R]`,
      );
    } else {
      const fieldsIndirect = afBody.match(/\/Fields\s+(\d+)\s+(\d+)\s+R/);
      if (fieldsIndirect) {
        // v0.8.2 — previously this case silently dropped every prior field.
        // Redefine the /Fields array object itself, appending the new ref.
        const fn = Number.parseInt(fieldsIndirect[1]!, 10);
        const fg = Number.parseInt(fieldsIndirect[2]!, 10);
        const inner = resolveArrayInner(fn, fg);
        extraParts.push({
          objNum: fn,
          genNum: fg,
          text: `${fn} ${fg} obj\n[${inner.length > 0 ? `${inner} ` : ''}${widgetObjNum} 0 R]\nendobj\n`,
        });
      } else {
        afBody = insertBeforeDictClose(afBody, `/Fields [${widgetObjNum} 0 R]`);
      }
    }
    const sigFlagsMatch = afBody.match(/\/SigFlags\s+\d+/);
    afBody = sigFlagsMatch
      ? afBody.replace(sigFlagsMatch[0], `/SigFlags ${newSigFlags}`)
      : insertBeforeDictClose(afBody, `/SigFlags ${newSigFlags}`);
    acroFormObjText = `${acroFormObjNum} ${acroFormGenNum} obj\n${afBody}\nendobj\n`;
  } else {
    acroFormObjText =
      `${acroFormObjNum} ${acroFormGenNum} obj\n` +
      `<< /Fields [${widgetObjNum} 0 R] /SigFlags 3 >>\n` +
      `endobj\n`;
  }

  // Updated Catalog — v0.8.2: preserve the prior catalog dict verbatim and
  // only replace/insert the /AcroForm entry (the old 3-key template dropped
  // /StructTreeRoot, /Lang, /Metadata, /MarkInfo, /PageLayout).
  const catalogBodyNew = upsertAcroFormRefInCatalog(
    info.catalogBody,
    `${acroFormObjNum} ${acroFormGenNum} R`,
  );
  const catalogObjText =
    `${info.catalogRef.objectNumber} ${info.catalogRef.generationNumber} obj\n` +
    `${catalogBodyNew}\n` +
    `endobj\n`;

  // Attach the widget to the target page's /Annots. Two shapes:
  //   - literal `/Annots [...]` (or no /Annots at all) → rewrite the page
  //     object with the widget appended/spliced (injectAnnot);
  //   - indirect `/Annots N G R` → redefine the array OBJECT itself with the
  //     widget appended and leave the page untouched (v0.8.2 — replacing the
  //     entry with `[N G R newRef]` nested the old array inside the new one,
  //     which is illegal per ISO 32000-1 §12.5.2 and made viewers drop every
  //     prior widget annotation, hiding existing signature stamps).
  const newAnnotRefs = `${widgetObjNum} 0 R${qrLinkPart ? ` ${qrLinkPart.objNum} 0 R` : ''}`;
  let pageObjText: string | null = null;
  const annotsLiteralMatch = targetPageBody.match(/\/Annots\s*\[([^\]]*)\]/);
  const annotsIndirectMatch = annotsLiteralMatch
    ? null
    : targetPageBody.match(/\/Annots\s+(\d+)\s+(\d+)\s+R/);
  if (annotsIndirectMatch) {
    const an = Number.parseInt(annotsIndirectMatch[1]!, 10);
    const ag = Number.parseInt(annotsIndirectMatch[2]!, 10);
    const inner = resolveArrayInner(an, ag);
    extraParts.push({
      objNum: an,
      genNum: ag,
      text: `${an} ${ag} obj\n[${inner.length > 0 ? `${inner} ` : ''}${newAnnotRefs}]\nendobj\n`,
    });
  } else {
    let pageBody = injectAnnot(targetPageBody, widgetObjNum, 0);
    if (qrLinkPart) pageBody = injectAnnot(pageBody, qrLinkPart.objNum, 0);
    pageObjText =
      `${targetPageRef.objectNumber} ${targetPageRef.generationNumber} obj\n` +
      `${pageBody}\n` +
      `endobj\n`;
  }

  // --- Assemble the appended tail ---
  // We must align so that /Contents starts at a known offset; we measure
  // offsets as we concatenate.
  //
  // v0.8.2 — the tail is encoded LATIN1 (1 char = 1 byte), not UTF-8: bodies
  // copied verbatim from the input (catalog, AcroForm, page, arrays) were
  // decoded as latin1, and UTF-8 re-encoding mangled any non-ASCII byte in
  // them (e.g. iText's UTF-16BE /Lang literal grew a doubled BOM, flagging
  // the revision as a suspicious modification). Our own generated text is
  // ASCII by construction (pdfStringLiteral hex-escapes non-ASCII).
  const inputLen = signedPdfBytes.length;

  // Some PDFs end without a trailing newline; ensure separation.
  const sep = signedPdfBytes[inputLen - 1] === 0x0a ? '' : '\n';

  // Body: Sig, AP, Widget, Catalog, AcroForm, then either the rewritten Page
  // (literal /Annots) or the redefined annots/fields array objects.
  // Order doesn't matter for correctness as long as xref reflects offsets.
  const parts: Array<{ objNum: number; genNum: number; text: string }> = [];
  parts.push({ objNum: sigObjNum, genNum: 0, text: sigObjText });
  parts.push({ objNum: apObjNum, genNum: 0, text: apObjText });
  parts.push({ objNum: widgetObjNum, genNum: 0, text: widgetObjText });
  if (qrLinkPart) parts.push(qrLinkPart);
  parts.push({
    objNum: info.catalogRef.objectNumber,
    genNum: info.catalogRef.generationNumber,
    text: catalogObjText,
  });
  parts.push({
    objNum: acroFormObjNum,
    genNum: acroFormGenNum,
    text: acroFormObjText,
  });
  if (pageObjText !== null) {
    parts.push({
      objNum: targetPageRef.objectNumber,
      genNum: targetPageRef.generationNumber,
      text: pageObjText,
    });
  }
  parts.push(...extraParts);

  // Concatenate body + record per-object byte offsets relative to file start.
  let cursor = inputLen + sep.length;
  const objectOffsets = new Map<number, { offset: number; gen: number }>();
  let bodyText = sep;
  for (const p of parts) {
    objectOffsets.set(p.objNum, { offset: cursor, gen: p.genNum });
    bodyText += p.text;
    cursor += p.text.length; // latin1: 1 char = 1 byte
  }

  // xref. Cross-ref needs subsections. We'll emit a single subsection 0..size-1
  // marking unaffected entries as "n 0000000000 65535 f" — wait, that's
  // wrong: classical PDF xref only carries entries for objects we list.
  // Incremental updates use multiple subsections. We compute the minimal
  // subsection set: free obj 0 + each updated/new obj.
  const newSize = nextObjNum;
  const xrefOffset = cursor;
  const xrefText = buildXref(objectOffsets, newSize);

  const trailerText =
    `trailer\n` +
    `<< /Size ${newSize} ` +
    `/Root ${info.catalogRef.objectNumber} ${info.catalogRef.generationNumber} R ` +
    `/Prev ${info.prevXrefOffset} >>\n` +
    `startxref\n${xrefOffset}\n` +
    `%%EOF\n`;

  const tail = latin1Encode(bodyText + xrefText + trailerText);
  const out = new Uint8Array(inputLen + tail.length);
  out.set(signedPdfBytes, 0);
  out.set(tail, inputLen);

  // --- Locate the placeholder /ByteRange + /Contents window in `out` and
  //     fill them in. We search ONLY past `inputLen` to avoid touching prior
  //     signatures' windows. ---
  const window = locateNewSigWindow(out, inputLen);

  // Real ByteRange covers everything except the /Contents hex bytes.
  const [, , ,] = [0, 0, 0, 0];
  const ltOffset = window.contentsHexStart - 1; // '<' position
  const gtOffset = window.contentsHexEnd; // '>' position
  const realByteRange: [number, number, number, number] = [
    0,
    ltOffset,
    gtOffset + 1,
    out.length - (gtOffset + 1),
  ];
  const brStr = `[ ${realByteRange[0]} ${realByteRange[1]} ${realByteRange[2]} ${realByteRange[3]} ]`;
  if (brStr.length > window.byteRangeSlotLen) {
    throw new SignerError(
      'incremental_update_failed',
      `ByteRange string (${brStr.length}) exceeds reserved slot (${window.byteRangeSlotLen})`,
    );
  }
  const padded = brStr.padEnd(window.byteRangeSlotLen, ' ');
  out.set(latin1Encode(padded), window.byteRangeSlotStart);

  // --- Hash covered bytes + build CMS ---
  const [a, b, c, d] = realByteRange;
  const covered = new Uint8Array(b + d);
  covered.set(out.subarray(a, a + b), 0);
  covered.set(out.subarray(c, c + d), b);

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

  const privateKey = await importPrivateKey(parsedPfx.privateKeyPkcs8Der, sigAlg);
  let cmsDer: Uint8Array;
  try {
    // F6: keep timestamp opt-out by default for incremental updates — the
    // top-level `signPdfPades` is the documented entry point for B-T.
    // F1: bundle arg intentionally omitted (as before F1) — defaults to the
    // full @firma-ec/tsl-ec set; aiaFallback threads opts.aiaFallback so the
    // multi-firma path gets the same AIA fallback + onChainResolution signal
    // as signPdfPades.
    const chainResolution = await resolveSigningIntermediates(
      parsedPfx.signingCert.der,
      parsedPfx.intermediates.map((cc) => cc.der),
      undefined,
      opts.aiaFallback,
    );
    const intermediateCertDers = chainResolution.ders;
    opts.onChainResolution?.({
      complete: chainResolution.complete,
      ...(chainResolution.missingIssuerDn !== undefined
        ? { missingIssuerDn: chainResolution.missingIssuerDn }
        : {}),
    });
    const cmsRes = await buildCmsSignedData({
      messageDigest,
      signerCertDer: parsedPfx.signingCert.der,
      intermediateCertDers,
      privateKey,
      sigAlg,
      signingTime,
      timestamp: false,
    });
    cmsDer = cmsRes.cms;
  } catch (cause) {
    throw new SignerError(
      'incremental_update_failed',
      `CMS build failed during incremental: ${cause instanceof Error ? cause.message : String(cause)}`,
      cause,
    );
  }

  const cmsHex = bytesToHex(cmsDer);
  const reservedHexLen = window.contentsHexEnd - window.contentsHexStart;
  if (cmsHex.length > reservedHexLen) {
    throw new SignerError(
      'signature_too_long',
      `CMS DER (${cmsDer.length} bytes) exceeds reserved /Contents window (${reservedHexLen / 2} bytes)`,
    );
  }
  const paddedHex = cmsHex.padEnd(reservedHexLen, '0');
  out.set(latin1Encode(paddedHex), window.contentsHexStart);

  // Reference remaining pdf-lib imports kept for API-shape stability.
  void PDFName;
  void PDFNumber;
  void PDFString;

  return out;
}

// ---------- Helpers ----------

/** Referencia indirecta a un objeto del árbol de páginas. */
interface PageRef {
  objectNumber: number;
  generationNumber: number;
}

interface PriorPdfInfo {
  prevXrefOffset: number;
  size: number;
  catalogRef: { objectNumber: number; generationNumber: number };
  /** Full raw body of the latest Catalog dict (v0.8.2 — preserved verbatim on update). */
  catalogBody: string;
  acroFormRef: { objectNumber: number; generationNumber: number } | null;
  /** Full raw body of the latest AcroForm dict, when present (v0.8.2 — preserved verbatim on update). */
  acroFormBody: string | null;
  firstPageRef: PageRef;
  firstPageBody: string;
  /**
   * Páginas REALES en orden de documento, resueltas recorriendo el árbol
   * `/Pages` completo (ver {@link collectPageRefs}). Antes era el `/Kids` de
   * primer nivel, que en un árbol anidado son nodos intermedios — defecto A1.
   */
  pageRefs: PageRef[];
}

/**
 * Parse the xref-stream object dictionary at `objOffset` and return the
 * trailer-equivalent fields. We do NOT decompress the xref data portion —
 * the only thing the incremental update needs from the prior xref is /Size +
 * /Root (PDF 1.5+ lets us emit a classic xref + classic trailer chained via
 * /Prev to the start of the old xref stream object — "hybrid" docs are valid
 * per ISO 32000-1 §7.5.8.4).
 *
 * Expects a structure like:
 *   N M obj
 *   <<
 *     /Type /XRef
 *     /Size 123
 *     /Root 1 0 R
 *     /W [ 1 3 1 ]
 *     /Length 456
 *     /Filter /FlateDecode
 *     …
 *   >>
 *   stream
 *   [binary]
 *   endstream
 *   endobj
 *
 * Throws when the dict isn't a /Type /XRef stream (caller should fall back
 * to the classic-xref-table parser).
 */
/**
 * Index just past the balanced `>>` that closes the dictionary starting at
 * `dictStart` (must point at `<<`). Nested dictionaries (e.g. an xref stream's
 * `/DecodeParms << ... >>`) are matched by depth so an inner `>>` doesn't
 * truncate the outer dict. Returns -1 if never balanced. Hex strings like
 * `/ID [<a1b2…>]` carry single `<`/`>`, never `<<`/`>>`, so they don't affect
 * the depth count.
 */
function balancedDictEnd(text: string, dictStart: number): number {
  let depth = 0;
  let i = dictStart;
  while (i < text.length) {
    if (text.startsWith('<<', i)) {
      depth++;
      i += 2;
      continue;
    }
    if (text.startsWith('>>', i)) {
      depth--;
      i += 2;
      if (depth === 0) return i;
      continue;
    }
    i++;
  }
  return -1;
}

/**
 * Pick a `/T` field name for the new signature widget that does NOT collide
 * with any existing terminal field name. Sequential `Signature<N>` starting at
 * `priorCount + 1`, skipping names already present. Exported for tests — a
 * collision makes viewers dedupe by name and drop a signature (real case:
 * Adobe-signed PDF whose existing field, compressed in an ObjStm, is named
 * `Signature2`, which the prior `priorCount + 1` formula reproduced verbatim).
 */
export function pickSignatureFieldName(existing: Set<string>, priorCount: number): string {
  let idx = priorCount + 1;
  let name = `Signature${idx}`;
  while (existing.has(name)) {
    idx += 1;
    name = `Signature${idx}`;
  }
  return name;
}

/** @internal Exported for regression tests (predictor-encoded xref streams). */
export function parseXrefStreamDict(
  text: string,
  objOffset: number,
): { size: number; rootObj: number; rootGen: number } {
  // Skip past `N M obj` token to the opening `<<`.
  const objStart = text.indexOf('<<', objOffset);
  if (objStart < 0 || objStart - objOffset > 64) {
    throw new Error(`xref-stream: '<<' not found near offset ${objOffset}`);
  }
  // Balanced scan for the OUTER dict close: an xref stream written by Adobe
  // (and any FlateDecode+PNG-predictor producer) carries a nested
  // `/DecodeParms << /Columns N /Predictor 12 >>` BEFORE `/Type /XRef`. A
  // plain `indexOf('>>')` stops at that inner close, truncating the dict so
  // `/Type /XRef` (and `/Size`/`/Root`) fall outside it → false "neither
  // classical xref table nor /Type /XRef stream" (bug: Adobe-signed PDFs).
  const dictEnd = balancedDictEnd(text, objStart);
  if (dictEnd < 0) throw new Error('xref-stream: dictionary close >> not found');
  const dict = text.substring(objStart, dictEnd);

  if (!/\/Type\s*\/XRef\b/.test(dict)) {
    throw new Error(
      `cross-reference at offset ${objOffset} is neither a classical xref table nor a /Type /XRef stream`,
    );
  }

  const sizeMatch = dict.match(/\/Size\s+(\d+)/);
  if (!sizeMatch) throw new Error('/Size missing in xref-stream dictionary');
  const rootMatch = dict.match(/\/Root\s+(\d+)\s+(\d+)\s+R/);
  if (!rootMatch) throw new Error('/Root missing in xref-stream dictionary');
  return {
    size: Number.parseInt(sizeMatch[1]!, 10),
    rootObj: Number.parseInt(rootMatch[1]!, 10),
    rootGen: Number.parseInt(rootMatch[2]!, 10),
  };
}

/**
 * Tope de nodos visitados al recorrer el árbol `/Pages`.
 *
 * Un documento real no pasa de unas pocas decenas de miles de nodos; el tope
 * existe para que un `/Kids` cíclico de un PDF malformado no cuelgue el worker
 * del lote (el `visited` ya corta los ciclos simples, esto acota también los
 * grafos con muchísimos nodos distintos).
 */
const MAX_PAGE_TREE_NODES = 50_000;

/** Refs `N G R` que aparecen dentro del `/Kids` de un nodo del árbol de páginas. */
function readKidsRefs(nodeBody: string): PageRef[] | null {
  // Una hoja declarada explícitamente es hoja aunque algo se le parezca.
  if (/\/Type\s*\/Page(?![a-zA-Z])/.test(nodeBody)) return null;
  const kidsMatch = nodeBody.match(/\/Kids\s*\[([^\]]*)\]/);
  if (!kidsMatch) return null;
  const refs: PageRef[] = [];
  for (const m of kidsMatch[1]!.matchAll(/(\d+)\s+(\d+)\s+R/g)) {
    refs.push({
      objectNumber: Number.parseInt(m[1]!, 10),
      generationNumber: Number.parseInt(m[2]!, 10),
    });
  }
  return refs;
}

/**
 * Recorre el árbol `/Pages` en profundidad y devuelve las PÁGINAS reales en
 * orden de documento, de modo que el índice 0-based que pide el llamante es el
 * mismo que ve un visor (y el mismo que usa `readPageGeometry`).
 *
 * Nodos intermedios (`/Pages` con `/Kids`) se atraviesan; hojas (`/Type /Page`,
 * o cualquier nodo sin `/Kids`) se acumulan. Un `/Kids` que se repite o que
 * cicla no se visita dos veces.
 */
function collectPageRefs(
  rootObjNum: number,
  rootGenNum: number,
  getBody: (objNum: number, genNum: number) => string | null,
): PageRef[] {
  const pages: PageRef[] = [];
  const visited = new Set<string>();
  const stack: PageRef[] = [{ objectNumber: rootObjNum, generationNumber: rootGenNum }];

  for (let budget = MAX_PAGE_TREE_NODES; stack.length > 0 && budget > 0; budget -= 1) {
    const node = stack.pop()!;
    const key = `${node.objectNumber} ${node.generationNumber}`;
    if (visited.has(key)) continue;
    visited.add(key);

    const body = getBody(node.objectNumber, node.generationNumber);
    if (body === null) continue;

    const kids = readKidsRefs(body);
    if (kids === null) {
      pages.push(node);
      continue;
    }
    // Pila LIFO: apilar al revés preserva el orden del documento.
    for (let i = kids.length - 1; i >= 0; i -= 1) stack.push(kids[i]!);
  }

  return pages;
}

function parsePriorPdf(
  pdf: Uint8Array,
  resolveCompressedBody?: (objNum: number, genNum: number) => string | null,
): PriorPdfInfo {
  const text = new TextDecoder('latin1').decode(pdf);
  /** Top-level scan first; fall back to the ObjStm-aware resolver (pdf-lib). */
  const getBody = (objNum: number, genNum: number): string | null =>
    readObjectBody(text, objNum, genNum) ?? resolveCompressedBody?.(objNum, genNum) ?? null;

  // Find the LAST `startxref` followed by digits.
  const startxrefMatches = [...text.matchAll(/startxref\s+(\d+)/g)];
  if (startxrefMatches.length === 0) throw new Error('startxref not found');
  const lastSx = startxrefMatches[startxrefMatches.length - 1]!;
  const prevXrefOffset = Number.parseInt(lastSx[1]!, 10);

  // Detect classical xref table vs xref stream (PDF 1.5+). Classical tables
  // start with the ASCII keyword `xref`; xref streams are objects (`N M obj`
  // followed by a `<<...>>` dict with `/Type /XRef`).
  let size: number;
  let catalogRef: { objectNumber: number; generationNumber: number };

  if (text.substring(prevXrefOffset, prevXrefOffset + 4) === 'xref') {
    // Classic xref table path.
    const trailerIdx = text.indexOf('trailer', prevXrefOffset);
    if (trailerIdx < 0) throw new Error('trailer not found after xref');
    const trailerEnd = text.indexOf('startxref', trailerIdx);
    if (trailerEnd < 0) throw new Error('trailer end (startxref) not found');
    const trailerBlock = text.substring(trailerIdx, trailerEnd);

    const sizeMatch = trailerBlock.match(/\/Size\s+(\d+)/);
    if (!sizeMatch) throw new Error('/Size missing in trailer');
    size = Number.parseInt(sizeMatch[1]!, 10);

    const rootMatch = trailerBlock.match(/\/Root\s+(\d+)\s+(\d+)\s+R/);
    if (!rootMatch) throw new Error('/Root missing in trailer');
    catalogRef = {
      objectNumber: Number.parseInt(rootMatch[1]!, 10),
      generationNumber: Number.parseInt(rootMatch[2]!, 10),
    };
  } else {
    // Xref-stream path (typical for PDF 1.5+ documents, including SRI
    // comprobantes). We append our classic xref+trailer with /Prev pointing
    // at the start of the prior xref-stream object — PDF spec §7.5.8.4
    // permits this "hybrid" update.
    const parsed = parseXrefStreamDict(text, prevXrefOffset);
    size = parsed.size;
    catalogRef = { objectNumber: parsed.rootObj, generationNumber: parsed.rootGen };
  }

  // Read the Catalog object body.
  const catalogBody = getBody(catalogRef.objectNumber, catalogRef.generationNumber);
  if (!catalogBody) throw new Error('Catalog object body not found');

  // Extract /Pages reference from Catalog.
  const pagesMatch = catalogBody.match(/\/Pages\s+(\d+)\s+(\d+)\s+R/);
  if (!pagesMatch) throw new Error('/Pages missing in Catalog');
  const pagesObjNum = Number.parseInt(pagesMatch[1]!, 10);
  const pagesGenNum = Number.parseInt(pagesMatch[2]!, 10);

  // Extract optional /AcroForm ref + its full body (preserved on update).
  const acroFormMatch = catalogBody.match(/\/AcroForm\s+(\d+)\s+(\d+)\s+R/);
  let acroFormRef: PriorPdfInfo['acroFormRef'] = null;
  let acroFormBody: string | null = null;
  if (acroFormMatch) {
    acroFormRef = {
      objectNumber: Number.parseInt(acroFormMatch[1]!, 10),
      generationNumber: Number.parseInt(acroFormMatch[2]!, 10),
    };
    acroFormBody = getBody(acroFormRef.objectNumber, acroFormRef.generationNumber);
  }

  // Resolve all page refs by WALKING the /Pages tree (defect A1).
  //
  // El código anterior leía el `/Kids` del nodo raíz con un regex y asumía
  // árbol PLANO. Con un árbol anidado — el que producen Acrobat y cualquier
  // herramienta de fusión — esa lista contiene los NODOS INTERMEDIOS, no las
  // páginas: `pageRefs.length` mentía (2 en vez de 6, medido) y el índice
  // 0-based que pide el llamante seleccionaba un nodo `/Pages`. Consecuencias
  // observadas, ambas reportadas como éxito: página fuera de rango ⇒ firma
  // INVISIBLE con `/Rect [0 0 0 0]`, y página 0 ⇒ widget colgado de un nodo
  // `/Pages` que no se renderiza en ninguna hoja.
  const pageRefs = collectPageRefs(pagesObjNum, pagesGenNum, getBody);
  if (pageRefs.length === 0) throw new Error('No pages found walking the /Pages tree');
  const firstPageRef = pageRefs[0]!;
  const firstPageBody = getBody(firstPageRef.objectNumber, firstPageRef.generationNumber);
  if (!firstPageBody) throw new Error('First page object body not found');

  return {
    prevXrefOffset,
    size,
    catalogRef,
    catalogBody,
    acroFormRef,
    acroFormBody,
    firstPageRef,
    firstPageBody,
    pageRefs,
  };
}

/**
 * Read an indirect object body (between `<< ... >>` or stream) given its
 * object/generation numbers. Returns the body text including the surrounding
 * dictionary `<< ... >>` (without the `objNum genNum obj\n ... endobj`
 * envelope). Returns null if not found.
 *
 * IMPORTANT: when multiple revisions exist (incremental updates), we want the
 * LATEST in-use object. We read the LAST occurrence in file order.
 */
function readObjectBody(text: string, objNum: number, genNum: number): string | null {
  const re = new RegExp(`\\b${objNum}\\s+${genNum}\\s+obj\\b`, 'g');
  const matches = [...text.matchAll(re)];
  if (matches.length === 0) return null;
  // Pick the last one (latest revision in classical PDFs).
  const last = matches[matches.length - 1]!;
  const startBody = last.index! + last[0].length;
  const endIdx = text.indexOf('endobj', startBody);
  if (endIdx < 0) return null;
  return text.substring(startBody, endIdx).trim();
}

/**
 * Inject `widgetRef` into a page object's `/Annots` LITERAL array, or splice
 * a fresh `/Annots` entry when the page has none.
 *
 * v0.8.2 — the indirect-ref case (`/Annots N G R`) is handled by the CALLER,
 * which redefines the referenced array object itself and leaves the page
 * untouched. The old behavior here (replacing the entry with a literal array
 * `[N G R newRef]`) nested the prior array as an /Annots ELEMENT — illegal
 * per ISO 32000-1 §12.5.2 — so viewers dropped every prior widget annotation
 * and existing signature stamps vanished.
 */
function injectAnnot(pageBody: string, widgetObjNum: number, widgetGenNum: number): string {
  const newRef = `${widgetObjNum} ${widgetGenNum} R`;
  const annotsLiteralMatch = pageBody.match(/\/Annots\s*\[([^\]]*)\]/);
  if (annotsLiteralMatch) {
    const inner = annotsLiteralMatch[1]!.trim();
    const replacement = `/Annots [${inner.length > 0 ? inner + ' ' : ''}${newRef}]`;
    return pageBody.replace(annotsLiteralMatch[0], replacement);
  }
  // No /Annots — splice into the dict before the closing `>>`.
  const dictClose = pageBody.lastIndexOf('>>');
  if (dictClose < 0) {
    // Wrap as a dict (defensive; shouldn't happen for valid pages).
    return `<< ${pageBody} /Annots [${newRef}] >>`;
  }
  return pageBody.substring(0, dictClose) + ` /Annots [${newRef}] ` + pageBody.substring(dictClose);
}

/**
 * Insert a `/Key value` entry right before the OUTER closing `>>` of a dict
 * body. The last `>>` in a well-formed dict body is always the outer close.
 */
function insertBeforeDictClose(dictBody: string, entry: string): string {
  const dictClose = dictBody.lastIndexOf('>>');
  if (dictClose < 0) return `<< ${dictBody} ${entry} >>`;
  return `${dictBody.substring(0, dictClose)} ${entry} ${dictBody.substring(dictClose)}`;
}

/**
 * Replace (or insert) the `/AcroForm` entry of a catalog dict body with
 * `/AcroForm <refStr>`, preserving every other key verbatim. Handles the
 * three shapes: indirect ref (`/AcroForm N G R`), inline dict
 * (`/AcroForm << ... >>`, balanced-scanned), or absent.
 */
function upsertAcroFormRefInCatalog(catalogBody: string, refStr: string): string {
  const indirect = catalogBody.match(/\/AcroForm\s+\d+\s+\d+\s+R/);
  if (indirect) {
    return catalogBody.replace(indirect[0], `/AcroForm ${refStr}`);
  }
  const tokenIdx = catalogBody.search(/\/AcroForm\b/);
  if (tokenIdx >= 0) {
    // Inline dict — excise the balanced << ... >> and replace with the ref.
    let i = tokenIdx + '/AcroForm'.length;
    while (i < catalogBody.length && /\s/.test(catalogBody[i]!)) i++;
    if (catalogBody.startsWith('<<', i)) {
      let depth = 0;
      let j = i;
      while (j < catalogBody.length) {
        if (catalogBody.startsWith('<<', j)) {
          depth++;
          j += 2;
          continue;
        }
        if (catalogBody.startsWith('>>', j)) {
          depth--;
          j += 2;
          if (depth === 0) break;
          continue;
        }
        j++;
      }
      return `${catalogBody.substring(0, tokenIdx)}/AcroForm ${refStr}${catalogBody.substring(j)}`;
    }
  }
  return insertBeforeDictClose(catalogBody, `/AcroForm ${refStr}`);
}

/**
 * Build a classical xref table for the given object offsets. We emit obj 0
 * + one subsection per contiguous run of touched objects.
 */
function buildXref(offsets: Map<number, { offset: number; gen: number }>, size: number): string {
  // Always include the free obj 0 sentinel (single-object subsection).
  // Then emit subsections for the touched objects.
  const touched = [...offsets.entries()].sort((a, b) => a[0] - b[0]);
  let out = `xref\n`;
  out += `0 1\n`;
  out += `0000000000 65535 f \n`;
  // Group consecutive obj numbers into subsections.
  let i = 0;
  while (i < touched.length) {
    const startObj = touched[i]![0];
    let j = i;
    while (j + 1 < touched.length && touched[j + 1]![0] === touched[j]![0] + 1) {
      j++;
    }
    const count = j - i + 1;
    out += `${startObj} ${count}\n`;
    for (let k = i; k <= j; k++) {
      const [, info] = touched[k]!;
      out += `${info.offset.toString().padStart(10, '0')} ${info.gen
        .toString()
        .padStart(5, '0')} n \n`;
    }
    i = j + 1;
  }
  void size;
  return out;
}

interface NewSigWindow {
  byteRangeSlotStart: number;
  byteRangeSlotLen: number;
  contentsHexStart: number;
  contentsHexEnd: number;
}

/** Locate the placeholder /ByteRange + /Contents in the freshly-appended tail. */
function locateNewSigWindow(out: Uint8Array, searchFrom: number): NewSigWindow {
  const text = new TextDecoder('latin1').decode(out);
  // Find the placeholder ByteRange (literal asterisks).
  const brIdx = text.indexOf('/ByteRange [ 0 **********0', searchFrom);
  if (brIdx < 0)
    throw new SignerError('incremental_update_failed', 'New /ByteRange placeholder not found');
  const openBr = text.indexOf('[', brIdx);
  const closeBr = text.indexOf(']', openBr);
  if (openBr < 0 || closeBr < 0)
    throw new SignerError('incremental_update_failed', 'New /ByteRange brackets not found');

  // Locate /Contents <...>
  const ctIdx = text.indexOf('/Contents', closeBr);
  if (ctIdx < 0) throw new SignerError('incremental_update_failed', 'New /Contents not found');
  let i = ctIdx + '/Contents'.length;
  while (i < out.length) {
    const b = out[i]!;
    if (b !== 0x20 && b !== 0x09 && b !== 0x0a && b !== 0x0d) break;
    i++;
  }
  if (out[i] !== 0x3c)
    throw new SignerError('incremental_update_failed', `Expected '<' at /Contents start`);
  const ltOffset = i;
  let j = i + 1;
  while (j < out.length && out[j] !== 0x3e) j++;
  if (j >= out.length)
    throw new SignerError('incremental_update_failed', 'New /Contents > not found');
  const gtOffset = j;

  return {
    byteRangeSlotStart: openBr,
    byteRangeSlotLen: closeBr - openBr + 1,
    contentsHexStart: ltOffset + 1,
    contentsHexEnd: gtOffset,
  };
}

/**
 * Encode a (latin1-range) string to bytes, 1 char = 1 byte. Total over the
 * tail by construction: copied bodies come from a latin1 decode and every
 * generated literal is ASCII (pdfStringLiteral hex-escapes the rest). A char
 * above U+00FF would silently corrupt offsets under UTF-8 — fail loud.
 */
function latin1Encode(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c > 0xff) {
      throw new SignerError(
        'incremental_update_failed',
        `Non-latin1 character U+${c.toString(16).toUpperCase()} in incremental tail`,
      );
    }
    out[i] = c;
  }
  return out;
}

function pdfStringLiteral(s: string): string {
  // Pure-ASCII strings → PDF literal with paren-escaping for ( ) \.
  // Anything else → UTF-16BE hex string with BOM (ISO 32000-1 §7.9.2.2), so
  // the emitted tail stays byte-safe under latin1 encoding and viewers
  // render accented names correctly (was UTF-8-mojibake before v0.8.2).
  if (/^[\x20-\x7e]*$/.test(s)) {
    const escaped = s.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
    return `(${escaped})`;
  }
  let hex = 'FEFF';
  for (let i = 0; i < s.length; i++) {
    hex += s.charCodeAt(i).toString(16).padStart(4, '0').toUpperCase();
  }
  return `<${hex}>`;
}

function pdfDateLiteral(d: Date): string {
  const pad = (n: number, w = 2): string => n.toString().padStart(w, '0');
  const y = d.getUTCFullYear();
  const mo = pad(d.getUTCMonth() + 1);
  const da = pad(d.getUTCDate());
  const hh = pad(d.getUTCHours());
  const mm = pad(d.getUTCMinutes());
  const ss = pad(d.getUTCSeconds());
  return `(D:${y}${mo}${da}${hh}${mm}${ss}Z)`;
}

function bytesToHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i]!.toString(16).padStart(2, '0');
  return s;
}
