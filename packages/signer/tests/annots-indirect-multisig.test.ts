/**
 * Regression v0.8.2: multi-firma sobre PDFs cuya página guarda /Annots como
 * REFERENCIA INDIRECTA a un array (iText/FirmaEC, Acrobat, etc.).
 *
 * Bug 2026-06-11 (reporte real, escrito legal multi-firmante): al añadir la
 * 2ª firma, `injectAnnot` reemplazaba `/Annots N G R` por
 * `/Annots [N G R <nuevo>]` — anidaba el ARRAY viejo como ELEMENTO de
 * /Annots, ilegal según ISO 32000-1 §12.5.2 (cada elemento debe ser un
 * diccionario de anotación). Los visores descartan la entrada no-dict → el
 * estampado visible de la firma previa (y cualquier Link de esa página)
 * dejaba de renderizarse, aunque ambas firmas seguían criptográficamente
 * válidas. Defecto independiente nº2: el catálogo se reconstruía con una
 * plantilla de 3 claves, perdiendo /StructTreeRoot /Lang /Metadata /MarkInfo
 * /PageLayout (→ SuspiciousModification en validadores estrictos como
 * pyHanko).
 *
 * Fix: con /Annots indirecto se redefine el PROPIO objeto array (mismo
 * número de objeto, widget anexado) y la página NO se toca — la estrategia
 * de iText/pyHanko. El catálogo y el AcroForm previos se preservan verbatim,
 * sustituyendo solo las entradas que cambian.
 *
 * Fixture: audit-075-2026.pdf (PDF real iText/FirmaEC de la regresión
 * v0.7.17 — 4 firmas previas, página 4 con /Annots indirecto).
 */

import { webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { PDFArray, PDFDict, PDFDocument, PDFName, PDFRef } from 'pdf-lib';
import * as pkijs from 'pkijs';
import { beforeAll, describe, expect, it } from 'vitest';

import { detectSignatures } from '../src/detectExistingSignatures.js';
import { addIncrementalSignature } from '../src/incrementalUpdate.js';
import { parsePfx } from '../src/p12.js';

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
const AUDIT_PDF = resolve(__dirname, '../../verifier/tests/fixtures/audit-075-2026.pdf');
// Página (0-based) cuyos /Annots son indirectos y albergan los widgets previos.
const TARGET_PAGE = 3;

function loadFixture(name: string): Uint8Array {
  return new Uint8Array(readFileSync(join(FIX_DIR, name)));
}

type IncArgs = Parameters<typeof addIncrementalSignature>;

/** Refs (como string "N G R") de los /Annots efectivos de una página. */
function annotRefStrings(doc: PDFDocument, pageIdx: number): string[] {
  const page = doc.getPage(pageIdx);
  const arr = page.node.Annots();
  if (!arr) return [];
  const out: string[] = [];
  for (let i = 0; i < arr.size(); i++) {
    out.push(arr.get(i)!.toString());
  }
  return out;
}

async function signOverAuditFixture(): Promise<{ input: Uint8Array; out: Uint8Array }> {
  const input = new Uint8Array(readFileSync(AUDIT_PDF));
  const pfx = await parsePfx(loadFixture('rsa2048-valid.p12'), PIN);
  const out = await addIncrementalSignature(input, pfx as IncArgs[1], {
    reason: 'regression annots indirecto',
    visibleSig: { page: TARGET_PAGE, x: 380, y: 40, width: 180, height: 60 },
  });
  return { input, out };
}

describe('multi-firma con /Annots indirecto (iText-style) — los widgets previos se preservan', () => {
  it('fixture sanity: la página objetivo tiene /Annots como referencia indirecta y catálogo con claves extra', async () => {
    const input = new Uint8Array(readFileSync(AUDIT_PDF));
    const doc = await PDFDocument.load(input, { updateMetadata: false });
    const rawAnnots = doc.getPage(TARGET_PAGE).node.get(PDFName.of('Annots'));
    expect(rawAnnots).toBeInstanceOf(PDFRef);
    // El catálogo real trae más claves que la plantilla mínima de 3.
    expect(doc.catalog.keys().length).toBeGreaterThan(3);
  });

  it('la página NO se reescribe y todos los /Annots efectivos siguen siendo dicts (widgets previos + nuevo)', async () => {
    const { input, out } = await signOverAuditFixture();

    // Invariante incremental: prefijo byte-idéntico.
    expect(out.length).toBeGreaterThan(input.length);
    expect(Buffer.from(out.subarray(0, input.length)).equals(Buffer.from(input))).toBe(true);

    const inDoc = await PDFDocument.load(input, { updateMetadata: false });
    const outDoc = await PDFDocument.load(out, { updateMetadata: false });

    // La página sigue apuntando al MISMO array indirecto (no fue reescrita).
    const rawAnnots = outDoc.getPage(TARGET_PAGE).node.get(PDFName.of('Annots'));
    expect(rawAnnots).toBeInstanceOf(PDFRef);

    // Todos los elementos del /Annots efectivo dereferencian a DICTS de
    // anotación — con el bug, el elemento 0 resolvía a un ARRAY anidado.
    const arr = outDoc.getPage(TARGET_PAGE).node.Annots();
    expect(arr).toBeInstanceOf(PDFArray);
    for (let i = 0; i < arr!.size(); i++) {
      const resolved = outDoc.context.lookup(arr!.get(i));
      expect(resolved).toBeInstanceOf(PDFDict);
    }

    // Los refs previos siguen colgados de la página; se suman el widget y el enlace QR.
    const inRefs = annotRefStrings(inDoc, TARGET_PAGE);
    const outRefs = annotRefStrings(outDoc, TARGET_PAGE);
    expect(inRefs.length).toBeGreaterThan(0);
    for (const r of inRefs) expect(outRefs).toContain(r);
    expect(outRefs.length).toBe(inRefs.length + 2);
    const addedTypes = [];
    for (let i = 0; i < arr!.size(); i++) {
      if (!inRefs.includes(arr!.get(i).toString())) {
        const annot = outDoc.context.lookup(arr!.get(i), PDFDict);
        addedTypes.push(annot.get(PDFName.of('Subtype'))!.toString());
      }
    }
    expect(addedTypes.sort()).toEqual(['/Link', '/Widget']);

    // Y hay una firma más que antes.
    const priorSigs = await detectSignatures(input);
    const outSigs = await detectSignatures(out);
    expect(outSigs.length).toBe(priorSigs.length + 1);
  }, 30000);

  it('el catálogo conserva TODAS sus claves previas (/StructTreeRoot, /Lang, /Metadata, …)', async () => {
    const { input, out } = await signOverAuditFixture();
    const inDoc = await PDFDocument.load(input, { updateMetadata: false });
    const outDoc = await PDFDocument.load(out, { updateMetadata: false });

    const inKeys = inDoc.catalog.keys().map((k) => k.toString());
    const outKeys = outDoc.catalog.keys().map((k) => k.toString());
    for (const k of inKeys) expect(outKeys).toContain(k);
  }, 30000);

  it('el AcroForm conserva los /Fields previos y suma el nuevo widget', async () => {
    const { input, out } = await signOverAuditFixture();
    const inDoc = await PDFDocument.load(input, { updateMetadata: false });
    const outDoc = await PDFDocument.load(out, { updateMetadata: false });

    const fieldsOf = (doc: PDFDocument): string[] => {
      const af = doc.catalog.lookup(PDFName.of('AcroForm'), PDFDict);
      const fields = af.lookup(PDFName.of('Fields'), PDFArray);
      const refs: string[] = [];
      for (let i = 0; i < fields.size(); i++) refs.push(fields.get(i)!.toString());
      return refs;
    };

    const inFields = fieldsOf(inDoc);
    const outFields = fieldsOf(outDoc);
    expect(inFields.length).toBeGreaterThan(0);
    for (const r of inFields) expect(outFields).toContain(r);
    expect(outFields.length).toBe(inFields.length + 1);
  }, 30000);
});
