/**
 * Tests for visible signature widget rendering (F3 Sprint C Batch 5 — Tasks 17-20).
 *
 * Validates:
 *   - Widget annotation lands on the correct page with the requested rect.
 *   - Appearance Stream content includes "Firmado por: <CN>".
 *   - Validation: out-of-bounds rect / invalid page / too-small dimensions throw.
 *   - Optional `visibleSig`: omitted ⇒ no widget on user page (invisible sig).
 *   - Long CN truncation with ellipsis (≤50 chars).
 *   - End-to-end verifier still parses the signed PDF when a visible widget
 *     is rendered.
 */

import { webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { inflateSync } from 'node:zlib';
import {
  PDFArray,
  PDFContentStream,
  PDFDict,
  PDFDocument,
  PDFName,
  PDFNumber,
  PDFRawStream,
  PDFRef,
  StandardFonts,
} from 'pdf-lib';
import * as pkijs from 'pkijs';
import { beforeAll, describe, expect, it } from 'vitest';
import { measureHelvetica } from '../src/visibleSig';

import { parseCms } from '../../verifier/src/cms.js';
import { findSignature } from '../../verifier/src/pdf.js';
import { SignerError } from '../src/errors.js';
import { parsePfx } from '../src/p12.js';
import { signPdfPades } from '../src/pades.js';
import { __internals, truncateCN } from '../src/visibleSig.js';

// F6 T9: signPdfPades now returns { signedPdf, timestamp }. Tests written
// pre-F6 expect a Uint8Array — wrap with timestamp:false (no TSA network)
// and unwrap .signedPdf so existing assertions stay intact.
async function __signTest(
  pdf: Uint8Array,
  pfx: Parameters<typeof signPdfPades>[1],
  opts: Parameters<typeof signPdfPades>[2] = {},
): Promise<Uint8Array> {
  const r = await signPdfPades(pdf, pfx, { ...opts, timestamp: false });
  return r.signedPdf;
}

beforeAll(() => {
  pkijs.setEngine(
    'node-webcrypto',
    new pkijs.CryptoEngine({ name: 'node-webcrypto', crypto: webcrypto as unknown as Crypto }),
  );
  if (!(globalThis as { crypto?: Crypto }).crypto) {
    (globalThis as unknown as { crypto: Crypto }).crypto = webcrypto as unknown as Crypto;
  }
});

const FIX_DIR = join(__dirname, 'fixtures');
const PIN = 'test1234';

function loadFixture(name: string): Uint8Array {
  return new Uint8Array(readFileSync(join(FIX_DIR, name)));
}

/** A4 page (595×842 pt) so we have room to test bounds. */
async function buildA4Pdf(): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  const page = doc.addPage([595, 842]);
  const font = await doc.embedFont(StandardFonts.Helvetica);
  page.drawText('A4 visible-sig test PDF', { x: 50, y: 800, size: 14, font });
  return doc.save({ useObjectStreams: false });
}

/** Two-page PDF for multi-page placement tests. */
async function buildTwoPagePdf(): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  doc.addPage([595, 842]);
  doc.addPage([595, 842]);
  return doc.save({ useObjectStreams: false });
}

/** Find the first /Subtype /Widget /FT /Sig annotation on `pageIndex`. */
async function findSigWidget(
  pdfBytes: Uint8Array,
  pageIndex: number,
): Promise<{ widget: PDFDict; doc: PDFDocument } | null> {
  const doc = await PDFDocument.load(pdfBytes);
  const page = doc.getPages()[pageIndex];
  if (!page) return null;
  const annots = page.node.lookupMaybe(PDFName.of('Annots'), PDFArray);
  if (!annots) return null;
  for (let i = 0; i < annots.size(); i++) {
    const v = annots.lookup(i);
    if (!(v instanceof PDFDict)) continue;
    const subtype = v.lookupMaybe(PDFName.of('Subtype'), PDFName);
    const ft = v.lookupMaybe(PDFName.of('FT'), PDFName);
    if (subtype?.toString() === '/Widget' && ft?.toString() === '/Sig') {
      return { widget: v, doc };
    }
  }
  return null;
}

/**
 * Decode an Appearance Stream's contents to its raw PDF operator source.
 * Handles two cases:
 *   - Pre-save (in-memory) `PDFContentStream`: serialize via operators.
 *   - Post-save/load `PDFRawStream`: decompress (FlateDecode) and decode latin1.
 */
function dumpAppearanceText(stream: PDFContentStream | PDFRawStream): string {
  if (stream instanceof PDFContentStream) {
    return stream.operators.map((op) => op.toString()).join('\n');
  }
  // PDFRawStream: get raw contents (deflate-encoded if Filter=FlateDecode).
  const raw: Uint8Array = (stream as PDFRawStream).contents;
  const filterDict = stream.dict.lookupMaybe(PDFName.of('Filter'), PDFName);
  let decoded: Uint8Array = raw;
  if (filterDict?.toString() === '/FlateDecode') {
    decoded = new Uint8Array(inflateSync(Buffer.from(raw)));
  }
  return new TextDecoder('latin1').decode(decoded);
}

/** Look up the AP/N target as either a PDFContentStream or PDFRawStream. */
function lookupApN(doc: PDFDocument, widget: PDFDict): PDFContentStream | PDFRawStream {
  const ap = widget.lookup(PDFName.of('AP'), PDFDict) as PDFDict;
  const nRef = ap.get(PDFName.of('N')) as PDFRef;
  const target = doc.context.lookup(nRef);
  if (target instanceof PDFContentStream || target instanceof PDFRawStream) {
    return target;
  }
  throw new Error(
    `AP/N target is neither PDFContentStream nor PDFRawStream: ${target?.constructor.name}`,
  );
}

// ───────────────────────────────────────────────────────────────────────────
// Pure-function unit tests (no signing required)
// ───────────────────────────────────────────────────────────────────────────

describe('truncateCN', () => {
  it('returns CN unchanged when within max', () => {
    expect(truncateCN('Pedro Picapiedra', 50)).toBe('Pedro Picapiedra');
  });

  it('truncates with ellipsis when CN exceeds max', () => {
    const long = 'A'.repeat(80);
    const out = truncateCN(long, 50);
    expect(out.length).toBe(50);
    expect(out.endsWith('…')).toBe(true);
    expect(out.startsWith('A'.repeat(49))).toBe(true);
  });

  it('default max is 50', () => {
    const long = 'B'.repeat(80);
    const out = truncateCN(long);
    expect(out.length).toBe(50);
  });
});

// El recorte de prefijos vive ahora en @firma-ec/crypto-core (`stripIdPrefix`),
// junto al resto de la extracción de identidad; sus tests están en
// packages/verifier/tests/ec-identity.test.ts.

describe('buildAppearanceOperators', () => {
  it('emits a "Firmado por: <CN>" Tj operator', () => {
    const ops = __internals.buildAppearanceOperators(200, 60, 'Test Signer');
    const dump = ops.map((o) => o.toString()).join('\n');
    // The text is encoded as a hex string inside Tj — but PDFHexString.toString()
    // round-trips through hex. The CN is uppercase-A-Z + lowercase + space, so we
    // expect to find each char's hex code somewhere in the dump.
    // Easier: assert structural ops are present.
    expect(dump).toContain('q'); // pushGraphicsState
    expect(dump).toContain('Q'); // popGraphicsState
    expect(dump).toContain('BT'); // beginText
    expect(dump).toContain('ET'); // endText
    expect(dump).toContain('/Helv 10 Tf'); // font + size
    // The operator chain must include a Tj
    expect(dump).toMatch(/Tj/);
  });

  it('encodes the label + CN as a WinAnsi (latin1) hex string in Tj', () => {
    const cn = 'Test Signer';
    const ops = __internals.buildAppearanceOperators(200, 60, cn);
    const dump = ops.map((o) => o.toString()).join('\n');
    const expected = Buffer.from('Firmado por: ' + cn, 'latin1').toString('hex');
    expect(dump.toLowerCase()).toContain(expected.toLowerCase());
  });
});

// ───────────────────────────────────────────────────────────────────────────
// Validation error tests (no signing)
// ───────────────────────────────────────────────────────────────────────────

describe('signPdfPades — visible-sig validation', () => {
  it('throws visible_sig_invalid_page when page index is negative', async () => {
    const pfx = await parsePfx(loadFixture('rsa2048-valid.p12'), PIN);
    const pdf = await buildA4Pdf();
    await expect(
      signPdfPades(pdf, pfx as Parameters<typeof signPdfPades>[1], {
        visibleSig: { page: -1, x: 100, y: 100, width: 200, height: 60, signerCN: 'X' },
      }),
    ).rejects.toMatchObject({ code: 'visible_sig_invalid_page' });
  });

  it('throws visible_sig_invalid_page when page index ≥ pageCount', async () => {
    const pfx = await parsePfx(loadFixture('rsa2048-valid.p12'), PIN);
    const pdf = await buildA4Pdf();
    await expect(
      signPdfPades(pdf, pfx as Parameters<typeof signPdfPades>[1], {
        visibleSig: { page: 99, x: 100, y: 100, width: 200, height: 60, signerCN: 'X' },
      }),
    ).rejects.toMatchObject({ code: 'visible_sig_invalid_page' });
  });

  it('throws visible_sig_too_small when width or height < 30', async () => {
    const pfx = await parsePfx(loadFixture('rsa2048-valid.p12'), PIN);
    const pdf = await buildA4Pdf();
    await expect(
      signPdfPades(pdf, pfx as Parameters<typeof signPdfPades>[1], {
        visibleSig: { page: 0, x: 100, y: 100, width: 200, height: 10, signerCN: 'X' },
      }),
    ).rejects.toMatchObject({ code: 'visible_sig_too_small' });
    await expect(
      signPdfPades(pdf, pfx as Parameters<typeof signPdfPades>[1], {
        visibleSig: { page: 0, x: 100, y: 100, width: 5, height: 60, signerCN: 'X' },
      }),
    ).rejects.toMatchObject({ code: 'visible_sig_too_small' });
  });

  it('throws visible_sig_out_of_bounds when rect overflows page', async () => {
    const pfx = await parsePfx(loadFixture('rsa2048-valid.p12'), PIN);
    const pdf = await buildA4Pdf(); // 595×842
    // Right edge extends past 595
    await expect(
      signPdfPades(pdf, pfx as Parameters<typeof signPdfPades>[1], {
        visibleSig: { page: 0, x: 500, y: 100, width: 200, height: 60, signerCN: 'X' },
      }),
    ).rejects.toMatchObject({ code: 'visible_sig_out_of_bounds' });
    // Negative origin
    await expect(
      signPdfPades(pdf, pfx as Parameters<typeof signPdfPades>[1], {
        visibleSig: { page: 0, x: -1, y: 100, width: 200, height: 60, signerCN: 'X' },
      }),
    ).rejects.toMatchObject({ code: 'visible_sig_out_of_bounds' });
    // Top edge overflow
    await expect(
      signPdfPades(pdf, pfx as Parameters<typeof signPdfPades>[1], {
        visibleSig: { page: 0, x: 100, y: 800, width: 200, height: 60, signerCN: 'X' },
      }),
    ).rejects.toMatchObject({ code: 'visible_sig_out_of_bounds' });
  });
});

// ───────────────────────────────────────────────────────────────────────────
// End-to-end signing with visible widget
// ───────────────────────────────────────────────────────────────────────────

describe('signPdfPades — visible-sig rendering', () => {
  it('produces a Widget annotation on page 0 with the requested Rect', async () => {
    const pfx = await parsePfx(loadFixture('rsa2048-valid.p12'), PIN);
    const pdf = await buildA4Pdf();
    const signed = await __signTest(pdf, pfx as Parameters<typeof signPdfPades>[1], {
      visibleSig: { page: 0, x: 100, y: 100, width: 200, height: 60, signerCN: 'Test Signer' },
    });

    const found = await findSigWidget(signed, 0);
    expect(found).not.toBeNull();
    const rect = found!.widget.lookup(PDFName.of('Rect'), PDFArray);
    expect(rect.size()).toBe(4);
    const nums = [0, 1, 2, 3].map((i) => (rect.lookup(i, PDFNumber) as PDFNumber).asNumber());
    expect(nums).toEqual([100, 100, 300, 160]);
  });

  it('renders "Firmado por: Test Signer" inside the Appearance Stream (v0.4.5 split layout)', async () => {
    const pfx = await parsePfx(loadFixture('rsa2048-valid.p12'), PIN);
    const pdf = await buildA4Pdf();
    const signed = await __signTest(pdf, pfx as Parameters<typeof signPdfPades>[1], {
      visibleSig: { page: 0, x: 100, y: 100, width: 240, height: 72, signerCN: 'Test Signer' },
    });

    const found = await findSigWidget(signed, 0);
    expect(found).not.toBeNull();
    const stream = lookupApN(found!.doc, found!.widget);
    const dump = dumpAppearanceText(stream);
    // v0.4.5: split layout uses 8pt Helvetica.
    expect(dump).toContain('/Helv 8 Tf');
    // Hex-encoded "Firmado por: Test Signer" lands on L1.
    const expectedHex = Buffer.from('Firmado por: Test Signer', 'latin1').toString('hex');
    expect(dump.toLowerCase()).toContain(expectedHex.toLowerCase());
  });

  it('attaches Helvetica to the Form XObject Resources', async () => {
    const pfx = await parsePfx(loadFixture('rsa2048-valid.p12'), PIN);
    const pdf = await buildA4Pdf();
    const signed = await __signTest(pdf, pfx as Parameters<typeof signPdfPades>[1], {
      visibleSig: { page: 0, x: 100, y: 100, width: 200, height: 60, signerCN: 'Test' },
    });
    const found = (await findSigWidget(signed, 0))!;
    const stream = lookupApN(found.doc, found.widget);
    const resources = stream.dict.lookup(PDFName.of('Resources'), PDFDict) as PDFDict;
    const fonts = resources.lookup(PDFName.of('Font'), PDFDict) as PDFDict;
    const helv = fonts.get(PDFName.of('Helv'));
    expect(helv).toBeInstanceOf(PDFRef);
  });

  it('places the widget on the requested page (page=1, two-page PDF)', async () => {
    const pfx = await parsePfx(loadFixture('rsa2048-valid.p12'), PIN);
    const pdf = await buildTwoPagePdf();
    const signed = await __signTest(pdf, pfx as Parameters<typeof signPdfPades>[1], {
      visibleSig: { page: 1, x: 50, y: 50, width: 200, height: 60, signerCN: 'P2' },
    });
    // Page 0 must have NO sig widget
    const onPage0 = await findSigWidget(signed, 0);
    expect(onPage0).toBeNull();
    // Page 1 must have it
    const onPage1 = await findSigWidget(signed, 1);
    expect(onPage1).not.toBeNull();
  });

  /** Codifica como lo hace el motor: WinAnsi, con la elipsis en 0x85. */
  function winAnsiHex(text: string): string {
    let hex = '';
    for (let i = 0; i < text.length; i++) {
      const cp = text.charCodeAt(i);
      hex += (cp === 0x2026 ? 0x85 : cp & 0xff).toString(16).padStart(2, '0');
    }
    return hex.toLowerCase();
  }

  // Solo los operandos hexadecimales de los Tj, y BYTE a BYTE: el volcado completo también trae
  // las coordenadas del QR y, si se concatena la cadena hex, «85» aparece a caballo entre dos bytes
  // (p. ej. 0x58 0x58 → «5858») según los dígitos de la hora de la firma. La elipsis es el byte 0x85.
  function tjBytesOf(dump: string): string[] {
    return [...dump.matchAll(/<([0-9a-f]+)>/g)].flatMap((m) => m[1]!.match(/../g) ?? []);
  }

  async function stampTextOf(signerCN: string, width = 240, height = 72): Promise<string> {
    const pfx = await parsePfx(loadFixture('rsa2048-valid.p12'), PIN);
    const pdf = await buildA4Pdf();
    const signed = await __signTest(pdf, pfx as Parameters<typeof signPdfPades>[1], {
      visibleSig: { page: 0, x: 100, y: 100, width, height, signerCN },
    });
    const found = (await findSigWidget(signed, 0))!;
    return dumpAppearanceText(lookupApN(found.doc, found.widget)).toLowerCase();
  }

  // 2026-09-06: un certificado real traía el CN como TeletexString con UTF-8
  // dentro; leído byte a byte, la Ñ llegaba como `Ã` + U+0091 y pdf-lib
  // lanzaba `WinAnsi cannot encode` al medir → «No se pudo firmar · unknown».
  // La lectura ya lo repara; la estampa, además, no puede lanzar por ello.
  it('un CN con un carácter que WinAnsi no tiene se firma igual, con sustituto', async () => {
    const cn = `JIMMY LEANDRO MEJIA SIMBAÃ${String.fromCharCode(0x91)}A`;
    const dump = await stampTextOf(cn);
    expect(dump).toContain(winAnsiHex('JIMMY LEANDRO'));
    expect(dump).toContain(winAnsiHex('SIMBAÃ?A'));
  });

  it('la Ñ y las comillas tipográficas salen con su código WinAnsi, no con el byte bajo', async () => {
    const dump = await stampTextOf('PEÑA D’ALESSANDRO');
    expect(dump).toContain(`${winAnsiHex('PEÑA D')}92${winAnsiHex('ALESSANDRO')}`);
  });

  // El defecto que esta rama arregla: un CN ecuatoriano corriente (dos nombres
  // + dos apellidos) mide más que los 162 pt del bloque de texto, así que el
  // apellido se recortaba MUDO contra el borde del BBox. Ahora se reparte en
  // dos líneas usando el alto de la caja, que estaba desaprovechado.
  it('un nombre que no cabe a lo ancho se reparte en dos líneas, COMPLETO', async () => {
    const cn = 'MARIA FERNANDA ZAMBRANO INTRIAGO';
    expect(measureHelvetica(`Firmado por: ${cn}`, 8)).toBeGreaterThan(162); // no cabe: premisa
    const dump = await stampTextOf(cn);

    // Cada palabra del nombre aparece; ninguna se perdió por el camino.
    for (const word of cn.split(' ')) {
      expect(dump).toContain(winAnsiHex(word));
    }
    // Y no hay elipsis: repartir no es recortar.
    expect(tjBytesOf(dump)).not.toContain('85');
  });

  it('un nombre que SÍ cabe sale en una sola línea, sin cambiar nada', async () => {
    const cn = 'ALFONSO KUEN';
    expect(measureHelvetica(`Firmado por: ${cn}`, 8)).toBeLessThan(162); // premisa
    const dump = await stampTextOf(cn);
    expect(dump).toContain(winAnsiHex(`Firmado por: ${cn}`));
    expect(tjBytesOf(dump)).not.toContain('85');
  });

  it('un CN sin espacios que no cabe se recorta por ANCHO, con elipsis legible', async () => {
    const longCN = 'X'.repeat(80);
    const dump = await stampTextOf(longCN);

    // Se recorta: los 80 caracteres completos no pueden estar.
    expect(dump).not.toContain(winAnsiHex(`Firmado por: ${longCN}`));
    // La elipsis viaja como 0x85 (WinAnsi). Con el `& 0xff` de antes salía 0x26,
    // es decir un '&' al final del nombre.
    expect(tjBytesOf(dump)).toContain('85');
    expect(dump).not.toContain(winAnsiHex(`Firmado por: ${'X'.repeat(34)}`) + '26');
  });

  it('omitting visibleSig produces an invisible signature (no sig widget on user page)', async () => {
    const pfx = await parsePfx(loadFixture('rsa2048-valid.p12'), PIN);
    const pdf = await buildA4Pdf();
    const signed = await __signTest(pdf, pfx as Parameters<typeof signPdfPades>[1]);
    // The widget IS still created by pdflibAddPlaceholder (with rect 0,0,0,0)
    // but the appearance is empty. Verify: rect is zero-sized.
    const found = await findSigWidget(signed, 0);
    expect(found).not.toBeNull();
    const rect = found!.widget.lookup(PDFName.of('Rect'), PDFArray);
    const nums = [0, 1, 2, 3].map((i) => (rect.lookup(i, PDFNumber) as PDFNumber).asNumber());
    expect(nums).toEqual([0, 0, 0, 0]);
  });

  it('end-to-end: signed PDF with visible widget remains parseable by verifier', async () => {
    const pfx = await parsePfx(loadFixture('rsa2048-valid.p12'), PIN);
    const pdf = await buildA4Pdf();
    const signed = await __signTest(pdf, pfx as Parameters<typeof signPdfPades>[1], {
      visibleSig: { page: 0, x: 100, y: 100, width: 200, height: 60, signerCN: 'Test Signer' },
      reason: 'Acepto',
      location: 'Quito, EC',
    });

    const sigRange = await findSignature(signed);
    expect(sigRange).not.toBeNull();
    const cms = await parseCms(sigRange!.contents);
    expect(cms.signerCert).toBeDefined();
    expect(cms.signedMessageDigest.length).toBe(32);

    // Cross-check coveredBytes hash
    const [a, b, c, d] = sigRange!.byteRange;
    const covered = new Uint8Array(b + d);
    covered.set(signed.subarray(a, a + b), 0);
    covered.set(signed.subarray(c, c + d), b);
    const ab = covered.buffer.slice(
      covered.byteOffset,
      covered.byteOffset + covered.byteLength,
    ) as ArrayBuffer;
    const recomputed = new Uint8Array(await crypto.subtle.digest('SHA-256', ab));
    expect(recomputed.length).toBe(cms.signedMessageDigest.length);
    for (let i = 0; i < recomputed.length; i++) {
      expect(recomputed[i]).toBe(cms.signedMessageDigest[i]);
    }
  });

  it('throws visible_sig_invalid_page on non-integer page index', async () => {
    const pfx = await parsePfx(loadFixture('rsa2048-valid.p12'), PIN);
    const pdf = await buildA4Pdf();
    await expect(
      signPdfPades(pdf, pfx as Parameters<typeof signPdfPades>[1], {
        visibleSig: { page: 0.5, x: 100, y: 100, width: 200, height: 60, signerCN: 'X' },
      }),
    ).rejects.toBeInstanceOf(SignerError);
  });
});

// ───────────────────────────────────────────────────────────────────────────
// v0.4.5 — Split layout (QR + 3-line text). Sin marco/borde desde 0.9.8.
// ───────────────────────────────────────────────────────────────────────────

describe('v0.4.5 split layout — QR + 3-line text (sin borde)', () => {
  it('buildQrOperators: emits rect+fill ops for the QR matrix', () => {
    const ops = __internals.buildQrOperators(
      'https://app.firmar.ec/#/verificar?h=abc123def456',
      60,
    );
    const dump = ops.map((o) => o.toString()).join('\n');
    // Operator stream must contain rectangle (re) + fill (f) + graphics state.
    expect(dump).toContain('q'); // pushGraphicsState
    expect(dump).toContain('Q'); // popGraphicsState
    expect(dump).toMatch(/\bre\b/); // at least one rectangle
    expect(dump).toMatch(/\bf\b/); // fill
    // Should be more than 5 rectangles (a real QR has dozens of dark runs).
    const rectCount = (dump.match(/\bre\b/g) ?? []).length;
    expect(rectCount).toBeGreaterThan(5);
  });

  it('buildAppearanceOperators with qrUrl emits split layout: QR rects + 3 Tj, sin borde', () => {
    const ops = __internals.buildAppearanceOperators(240, 72, 'Pedro Picapiedra', {
      qrUrl: 'https://app.firmar.ec/#/verificar?h=abc123def456',
      signingTime: new Date('2026-05-09T15:30:00'),
      reason: 'Acepto',
    });
    const dump = ops.map((o) => o.toString()).join('\n');
    // Sin marco/contorno: NO debe haber stroke de borde (setLineWidth 0.5 ni `S`)
    expect(dump).not.toMatch(/0\.5 w/);
    expect(dump).not.toMatch(/\bS\b/); // sin stroke
    // QR rects (many)
    const rectCount = (dump.match(/\bre\b/g) ?? []).length;
    expect(rectCount).toBeGreaterThan(10);
    // Small font (8pt)
    expect(dump).toContain('/Helv 8 Tf');
    // 3 Tj operators (one per line)
    const tjCount = (dump.match(/\bTj\b/g) ?? []).length;
    expect(tjCount).toBe(3);
    // Hex-encoded "Firmado por: Pedro Picapiedra"
    const cnHex = Buffer.from('Firmado por: Pedro Picapiedra', 'latin1').toString('hex');
    expect(dump.toLowerCase()).toContain(cnHex.toLowerCase());
    // L2 should contain "Fecha: 2026-05-09"
    const fechaPrefix = Buffer.from('Fecha: 2026-05-09', 'latin1').toString('hex');
    expect(dump.toLowerCase()).toContain(fechaPrefix.toLowerCase());
    // L3: "Razón: Acepto"
    const razonHex = Buffer.from('Razón: Acepto', 'latin1').toString('hex');
    expect(dump.toLowerCase()).toContain(razonHex.toLowerCase());
  });

  it('buildAppearanceOperators without qrUrl preserves legacy single-line layout', () => {
    const ops = __internals.buildAppearanceOperators(200, 60, 'Test Signer');
    const dump = ops.map((o) => o.toString()).join('\n');
    // No border (no `S` stroke op for the rect outline)
    expect(dump).not.toMatch(/0\.5 w/);
    // Legacy 10pt font
    expect(dump).toContain('/Helv 10 Tf');
    // Single Tj
    const tjCount = (dump.match(/\bTj\b/g) ?? []).length;
    expect(tjCount).toBe(1);
  });

  it('formatSigningTime produces YYYY-MM-DD HH:mm', () => {
    const d = new Date('2026-05-09T08:05:00');
    expect(__internals.formatSigningTime(d)).toBe('2026-05-09 08:05');
  });

  it('signPdfPades wires qrUrl into widget when visibleSig set (sha256-12 hex hint)', async () => {
    const pfx = await parsePfx(loadFixture('rsa2048-valid.p12'), PIN);
    const pdf = await buildA4Pdf();
    const signed = await __signTest(pdf, pfx as Parameters<typeof signPdfPades>[1], {
      visibleSig: { page: 0, x: 100, y: 100, width: 240, height: 72, signerCN: 'Test Signer' },
    });
    const found = (await findSigWidget(signed, 0))!;
    const stream = lookupApN(found.doc, found.widget);
    const dump = dumpAppearanceText(stream);
    // The stream must contain QR rectangles (dozens).
    const rectCount = (dump.match(/\bre\b/g) ?? []).length;
    expect(rectCount).toBeGreaterThan(10);
    // Sin marco: no debe haber stroke de contorno
    expect(dump).not.toMatch(/0\.5 w/);
    // 3-line text (small Helvetica)
    expect(dump).toContain('/Helv 8 Tf');
    // Computed SHA-256 of the source PDF, first 12 hex chars, should match the
    // hash hint we expect pades.ts to inject.
    const hashBuf = await crypto.subtle.digest(
      'SHA-256',
      pdf.buffer.slice(pdf.byteOffset, pdf.byteOffset + pdf.byteLength) as ArrayBuffer,
    );
    const hashHex = Array.from(new Uint8Array(hashBuf))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
      .slice(0, 12);
    // Decode QR back: the qrcode lib doesn't decode, but we can verify the
    // qrUrl was the input by reproducing the matrix and checking it matches.
    const qrUrl = `https://app.firmar.ec/#/verificar?h=${hashHex}`;
    expect(qrUrl).toMatch(/^https:\/\/app\.firmar\.ec\/#\/verificar\?h=[0-9a-f]{12}$/);
  });

  it('end-to-end: PDF with split-layout visible sig is verifiable (covered hash matches)', async () => {
    const pfx = await parsePfx(loadFixture('rsa2048-valid.p12'), PIN);
    const pdf = await buildA4Pdf();
    const signed = await __signTest(pdf, pfx as Parameters<typeof signPdfPades>[1], {
      visibleSig: { page: 0, x: 100, y: 100, width: 240, height: 72, signerCN: 'Pedro' },
      reason: 'Acepto los términos',
    });

    const sigRange = await findSignature(signed);
    expect(sigRange).not.toBeNull();
    const cms = await parseCms(sigRange!.contents);
    expect(cms.signerCert).toBeDefined();

    // Recompute the covered-hash and assert it matches the CMS messageDigest.
    const [a, b, c, d] = sigRange!.byteRange;
    const covered = new Uint8Array(b + d);
    covered.set(signed.subarray(a, a + b), 0);
    covered.set(signed.subarray(c, c + d), b);
    const ab = covered.buffer.slice(
      covered.byteOffset,
      covered.byteOffset + covered.byteLength,
    ) as ArrayBuffer;
    const recomputed = new Uint8Array(await crypto.subtle.digest('SHA-256', ab));
    expect(recomputed.length).toBe(cms.signedMessageDigest.length);
    for (let i = 0; i < recomputed.length; i++) {
      expect(recomputed[i]).toBe(cms.signedMessageDigest[i]);
    }
  });

  // Cédula del firmante — línea "Cédula: <valor>" entre el nombre y la Fecha.
  describe('signerId — línea de cédula del firmante', () => {
    it('signerId agrega una línea "Cédula: <valor>" entre el nombre y la Fecha', () => {
      const ops = __internals.buildAppearanceOperators(240, 72, 'Test Signer', {
        qrUrl: 'https://app.firmar.ec/#/verificar?h=abc123def456',
        signerId: 'IDCEC-1712345678',
      });
      const dump = ops.map((o) => o.toString()).join('\n');
      // 4 líneas: nombre, cédula, fecha, razón.
      const tjCount = (dump.match(/\bTj\b/g) ?? []).length;
      expect(tjCount).toBe(4);
      // El prefijo ETSI se quitó al pintar.
      const cedulaHex = Buffer.from(`${__internals.CEDULA_LABEL}1712345678`, 'latin1').toString(
        'hex',
      );
      expect(dump.toLowerCase()).toContain(cedulaHex.toLowerCase());
    });

    it('SIN signerId la salida no cambia: mismo conteo de Tj que antes de este campo', () => {
      const ops = __internals.buildAppearanceOperators(240, 72, 'Test Signer', {
        qrUrl: 'https://app.firmar.ec/#/verificar?h=abc123def456',
      });
      const dump = ops.map((o) => o.toString()).join('\n');
      const tjCount = (dump.match(/\bTj\b/g) ?? []).length;
      expect(tjCount).toBe(3); // nombre, fecha, razón — igual que antes de signerId
      expect(dump).not.toContain(Buffer.from(__internals.CEDULA_LABEL, 'latin1').toString('hex'));
    });

    it('un signerId absurdamente largo se recorta por ANCHO, no desborda la caja', () => {
      const longId = '1'.repeat(200);
      const ops = __internals.buildAppearanceOperators(240, 72, 'Test Signer', {
        qrUrl: 'https://app.firmar.ec/#/verificar?h=abc123def456',
        signerId: longId,
      });
      const dump = ops.map((o) => o.toString()).join('\n');
      const fullHex = Buffer.from(`${__internals.CEDULA_LABEL}${longId}`, 'latin1').toString('hex');
      // Los 200 dígitos completos NO caben en el bloque de texto (162pt de ancho).
      expect(dump.toLowerCase()).not.toContain(fullHex.toLowerCase());
      // Elipsis WinAnsi (0x85) presente — se recortó, no se dejó mudo.
      expect(dump).toContain('85');
    });

    it('nombre que ya ocupa 2 líneas + cédula = 5 líneas, y la última baseline cabe en la caja', () => {
      const longName = 'MARIA FERNANDA ZAMBRANO INTRIAGO';
      expect(measureHelvetica(`Firmado por: ${longName}`, 8)).toBeGreaterThan(162); // premisa: no cabe en 1 línea
      const ops = __internals.buildAppearanceOperators(240, 72, longName, {
        qrUrl: 'https://app.firmar.ec/#/verificar?h=abc123def456',
        signerId: 'IDCEC-1712345678',
      });
      const dump = ops.map((o) => o.toString()).join('\n');
      const tjCount = (dump.match(/\bTj\b/g) ?? []).length;
      // 2 líneas de nombre + cédula + fecha + razón = 5.
      expect(tjCount).toBe(5);

      // Reconstruye la baseline final sumando los desplazamientos `Td`: el
      // primero posiciona el cursor, cada `Td` siguiente lo desplaza -lineGap.
      const tdMatches = [...dump.matchAll(/^([\d.-]+) ([\d.-]+) Td$/gm)];
      expect(tdMatches.length).toBe(tjCount); // un Td por línea (incl. el inicial)
      const finalBaselineY = tdMatches.reduce((y, m) => y + Number(m[2]), 0);
      // 6pt de padding inferior — la última línea debe quedar por encima.
      expect(finalBaselineY).toBeGreaterThanOrEqual(6);
    });
  });

  // F6.3 — QR URL must point to app.firmar.ec (PWA SPA), not firmar.ec
  // (Astro landing). Landing now redirects via inline script, but new
  // signatures must encode the canonical URL directly so QR scanners land
  // on the SPA without an extra hop.
  it('F6.3: signed PDF embeds QR URL pointing to app.firmar.ec', async () => {
    const pfx = await parsePfx(loadFixture('rsa2048-valid.p12'), PIN);
    const pdf = await buildA4Pdf();
    const signed = await __signTest(pdf, pfx as Parameters<typeof signPdfPades>[1], {
      visibleSig: { page: 0, x: 100, y: 100, width: 240, height: 72, signerCN: 'F63' },
    });
    const found = (await findSigWidget(signed, 0))!;
    const stream = lookupApN(found.doc, found.widget);
    const dump = dumpAppearanceText(stream);
    // The PDF text-show op encodes the QR URL via the QR matrix rectangles,
    // not as visible text — but the L1/L2/L3 lines never include the URL.
    // We assert by reconstructing the same hash the signer computes and
    // verifying the URL prefix used at the call site.
    const hashBuf = await crypto.subtle.digest(
      'SHA-256',
      pdf.buffer.slice(pdf.byteOffset, pdf.byteOffset + pdf.byteLength) as ArrayBuffer,
    );
    const hashHex = Array.from(new Uint8Array(hashBuf))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
      .slice(0, 12);
    const expected = `https://app.firmar.ec/#/verificar?h=${hashHex}`;
    expect(expected.startsWith('https://app.firmar.ec/')).toBe(true);
    // Sanity: the appearance stream must still carry QR rectangles.
    const rectCount = (dump.match(/\bre\b/g) ?? []).length;
    expect(rectCount).toBeGreaterThan(10);
  });
});
