/**
 * El QR estampado en el PDF firmado codifica el TEXTO de `buildQrPayload`
 * (quién firmó, DN del certificado, con qué, fecha, enlace), no solo la URL.
 * Se compara la matriz estampada (rectángulos del AP/N) contra la matriz que
 * produce `buildQrOperators` para el texto esperado, y contra la de la URL sola
 * como control negativo.
 */
import { webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inflateSync } from 'node:zlib';
import {
  PDFArray,
  PDFDict,
  PDFDocument,
  PDFName,
  PDFRawStream,
  type PDFRef,
  StandardFonts,
} from 'pdf-lib';
import { beforeAll, describe, expect, it } from 'vitest';
import { addIncrementalSignature } from '../src/incrementalUpdate.js';
import { parsePfx } from '../src/p12.js';
import { signPdfPades } from '../src/pades.js';
import { buildQrPayload, subjectDnFromDer } from '../src/qrPayload.js';
import { buildVerifyQrUrl } from '../src/verifyUrl.js';
import { buildQrOperators } from '../src/visibleSig.js';

const FIX_DIR = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const PIN = 'test1234';
const PADDING = 6; // visibleSig.ts PADDING_PT: el QR arranca en (6, 6)
const QR_AREA = 60;

beforeAll(() => {
  if (!(globalThis as { crypto?: Crypto }).crypto) {
    (globalThis as unknown as { crypto: Crypto }).crypto = webcrypto as unknown as Crypto;
  }
});

async function a4(): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  const page = doc.addPage([595, 842]);
  page.drawText('qr payload', {
    x: 50,
    y: 700,
    font: await doc.embedFont(StandardFonts.Helvetica),
  });
  return doc.save();
}

/** Rectángulos de módulo del QR (alto < 2 pt) del AP/N de la ÚLTIMA firma visible, ordenados. */
async function stampedQrRects(signedPdf: Uint8Array): Promise<string[]> {
  const loaded = await PDFDocument.load(signedPdf);
  const annots = loaded.getPages()[0]!.node.lookupMaybe(PDFName.of('Annots'), PDFArray)!;
  let apStream: PDFRawStream | undefined;
  for (let i = 0; i < annots.size(); i++) {
    const annot = annots.lookup(i);
    if (!(annot instanceof PDFDict)) continue;
    if (annot.lookupMaybe(PDFName.of('FT'), PDFName)?.toString() !== '/Sig') continue;
    const ap = annot.lookupMaybe(PDFName.of('AP'), PDFDict);
    if (!ap) continue;
    const target = loaded.context.lookup(ap.get(PDFName.of('N')) as PDFRef);
    if (target instanceof PDFRawStream) apStream = target;
  }
  expect(apStream).toBeDefined();
  const raw = apStream!.contents;
  const filter = apStream!.dict.get(PDFName.of('Filter'))?.toString();
  const text = new TextDecoder('latin1').decode(
    filter === '/FlateDecode' ? new Uint8Array(inflateSync(Buffer.from(raw))) : raw,
  );
  return [...text.matchAll(/([\d.]+) ([\d.]+) ([\d.]+) ([\d.]+) re/g)]
    .map((m) => [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])] as const)
    .filter(([, , , h]) => h < 2)
    .map(([x, y, w, h]) => [x, y, w, h].map((v) => v.toFixed(3)).join(' '))
    .sort();
}

describe('QR estampado en el PDF firmado', () => {
  it('codifica el texto con firmante, DN, fecha y enlace, no solo la URL', async () => {
    const pfx = await parsePfx(
      new Uint8Array(readFileSync(join(FIX_DIR, 'rsa2048-valid.p12'))),
      PIN,
    );
    const pdf = await a4();
    const signingTime = new Date(Date.UTC(2026, 9, 21, 14, 26, 4, 492));
    const result = await signPdfPades(pdf, pfx as Parameters<typeof signPdfPades>[1], {
      signingTime,
      timestamp: false,
      visibleSig: {
        page: 0,
        x: 100,
        y: 100,
        width: 240,
        height: 72,
        signerCN: pfx.signingCert.subjectCN,
      },
    });

    const stamped = await stampedQrRects(result.signedPdf);

    const shift = (ops: ReturnType<typeof buildQrOperators>): string[] =>
      ops
        .map((op) => op.toString())
        .map((s) => /^([\d.]+) ([\d.]+) ([\d.]+) ([\d.]+) re$/.exec(s))
        .filter((m): m is RegExpExecArray => m !== null)
        .map((m) =>
          [Number(m[1]) + PADDING, Number(m[2]) + PADDING, Number(m[3]), Number(m[4])]
            .map((v) => v.toFixed(3))
            .join(' '),
        )
        .sort();

    // La URL real depende del hash del PDF de entrada: se reproduce igual que pades.ts.
    const hash = Buffer.from(await crypto.subtle.digest('SHA-256', pdf))
      .toString('hex')
      .slice(0, 12);
    const verifyUrl = buildVerifyQrUrl(hash);
    const payload = buildQrPayload({
      signerName: pfx.signingCert.subjectCN,
      subjectDn: subjectDnFromDer(pfx.signingCert.der),
      verifyUrl,
      signingTime,
    });

    expect(stamped.length).toBeGreaterThan(50);
    expect(stamped).toEqual(shift(buildQrOperators(payload, QR_AREA)));
    // Control negativo: ya no es la matriz de la URL sola.
    expect(stamped).not.toEqual(shift(buildQrOperators(verifyUrl, QR_AREA)));
  });

  it('la firma incremental (2.ª firma) estampa el mismo texto en el QR', async () => {
    const pfx = await parsePfx(
      new Uint8Array(readFileSync(join(FIX_DIR, 'rsa2048-valid.p12'))),
      PIN,
    );
    const first = await signPdfPades(await a4(), pfx as Parameters<typeof signPdfPades>[1], {
      timestamp: false,
    });
    const signingTime = new Date(Date.UTC(2026, 9, 22, 15, 0, 1, 7));
    const second = await addIncrementalSignature(
      first.signedPdf,
      pfx as Parameters<typeof addIncrementalSignature>[1],
      {
        signingTime,
        visibleSig: {
          page: 0,
          x: 100,
          y: 300,
          width: 240,
          height: 72,
          signerCN: pfx.signingCert.subjectCN,
        },
      },
    );
    const stamped = await stampedQrRects(second);
    const hash = Buffer.from(await crypto.subtle.digest('SHA-256', first.signedPdf))
      .toString('hex')
      .slice(0, 12);
    const verifyUrl = buildVerifyQrUrl(hash);
    const payload = buildQrPayload({
      signerName: pfx.signingCert.subjectCN,
      subjectDn: subjectDnFromDer(pfx.signingCert.der),
      verifyUrl,
      signingTime,
    });
    const shifted = buildQrOperators(payload, QR_AREA)
      .map((op) => /^([\d.]+) ([\d.]+) ([\d.]+) ([\d.]+) re$/.exec(op.toString()))
      .filter((m): m is RegExpExecArray => m !== null)
      .map((m) =>
        [Number(m[1]) + PADDING, Number(m[2]) + PADDING, Number(m[3]), Number(m[4])]
          .map((v) => v.toFixed(3))
          .join(' '),
      )
      .sort();
    expect(stamped.length).toBeGreaterThan(50);
    expect(stamped).toEqual(shifted);
  });
});
