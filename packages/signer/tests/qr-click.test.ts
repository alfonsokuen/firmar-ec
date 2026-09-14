import { createHash, webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { PDFDocument, PDFName, degrees } from 'pdf-lib';
import { getDocument } from 'pdfjs-dist/legacy/build/pdf.mjs';
import * as pkijs from 'pkijs';
import { beforeAll, describe, expect, it } from 'vitest';
import { verifyPdf } from '../../verifier/src/index.js';
import { addIncrementalSignature } from '../src/incrementalUpdate.js';
import { parsePfx } from '../src/p12.js';
import { signPdfPades } from '../src/pades.js';
import { buildVerifyQrUrl } from '../src/verifyUrl.js';

let pfx: Awaited<ReturnType<typeof parsePfx>>;
const offline = { timestamp: false, ltv: { enabled: false }, aiaFallback: null } as const;
beforeAll(async () => {
  pkijs.setEngine(
    'node-webcrypto',
    new pkijs.CryptoEngine({ name: 'node-webcrypto', crypto: webcrypto as unknown as Crypto }),
  );
  pfx = await parsePfx(
    new Uint8Array(readFileSync(join(__dirname, 'fixtures/rsa2048-valid.p12'))),
    'test1234',
  );
});

async function source(rotate = 0, indirect = false) {
  const doc = await PDFDocument.create();
  doc.addPage([600, 800]);
  const page = doc.addPage([600, 800]);
  page.setRotation(degrees(rotate));
  if (indirect) page.node.set(PDFName.of('Annots'), doc.context.register(doc.context.obj([])));
  return doc.save({ useObjectStreams: false });
}

async function annotations(bytes: Uint8Array, pageNumber: number) {
  const pdf = await getDocument({ data: bytes.slice(), isEvalSupported: false }).promise;
  try {
    return await (await pdf.getPage(pageNumber)).getAnnotations();
  } finally {
    await pdf.destroy();
  }
}

function expectedUrl(bytes: Uint8Array) {
  return buildVerifyQrUrl(createHash('sha256').update(bytes).digest('hex').slice(0, 12));
}

const cases = [
  { rotate: 0, first: [46, 76, 106, 136], next: [46, 104, 106, 164] },
  { rotate: 90, first: [46, 244, 106, 304], next: [74, 244, 134, 304] },
  { rotate: 180, first: [214, 104, 274, 164], next: [214, 76, 274, 136] },
  { rotate: 270, first: [74, 76, 134, 136], next: [46, 76, 106, 136] },
] as const;

describe('QR links in the signed PDF as read by PDF.js', () => {
  for (const c of cases) {
    const placement = {
      page: 1,
      x: 40,
      y: 70,
      width: c.rotate % 180 ? 100 : 240,
      height: c.rotate % 180 ? 240 : 100,
      rotate: c.rotate,
      signerCN: 'Test Signer',
    };
    it(`first signature: clickable QR on the target page, rotation ${c.rotate}`, async () => {
      const input = await source(c.rotate);
      const { signedPdf } = await signPdfPades(input, pfx, { ...offline, visibleSig: placement });
      const annots = await annotations(signedPdf, 2);
      const links = annots.filter((a) => a.subtype === 'Link');
      expect(links).toHaveLength(1);
      expect(links[0].url).toBe(expectedUrl(input));
      expect(links[0].rect).toEqual(c.first);
      expect(annots.filter((a) => a.subtype === 'Widget' && a.fieldType === 'Sig')).toHaveLength(1);
      expect((await annotations(signedPdf, 1)).filter((a) => a.subtype === 'Link')).toHaveLength(0);
      const verified = await verifyPdf(signedPdf, { trustRoots: [], fetchOcsp: false });
      expect(verified.integrity?.digestMatches).toBe(true);
    });

    it(`incremental signature preserves previous bytes and QR, rotation ${c.rotate}`, async () => {
      const input = await source(c.rotate, true);
      const { signedPdf: first } = await signPdfPades(input, pfx, {
        ...offline,
        visibleSig: { ...placement, x: 300 },
      });
      const next = await addIncrementalSignature(first, pfx, { ...offline, visibleSig: placement });
      expect(Buffer.from(next.subarray(0, first.length)).equals(Buffer.from(first))).toBe(true);
      const annots = await annotations(next, 2);
      const links = annots.filter((a) => a.subtype === 'Link');
      expect(links).toHaveLength(2);
      expect(links.map((a) => a.url)).toEqual([expectedUrl(input), expectedUrl(first)]);
      expect(links[1].rect).toEqual(c.next);
      expect(annots.filter((a) => a.subtype === 'Widget' && a.fieldType === 'Sig')).toHaveLength(2);
      const verified = await verifyPdf(next, { trustRoots: [], fetchOcsp: false });
      expect(verified.integrity?.digestMatches).toBe(true);
    });
  }

  it('invisible signatures do not add a clickable area', async () => {
    const { signedPdf } = await signPdfPades(await source(), pfx, offline);
    const next = await addIncrementalSignature(signedPdf, pfx, offline);
    expect((await annotations(next, 1)).filter((a) => a.subtype === 'Link')).toHaveLength(0);
  });
});
