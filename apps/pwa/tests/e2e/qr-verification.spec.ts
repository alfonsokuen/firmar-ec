import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { type Page, expect, test } from '@playwright/test';
import { getDocument } from 'pdfjs-dist/legacy/build/pdf.mjs';
import { verifyPadesIndependently } from './helpers/lote-verify';

const HERE = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const PDFJS = dirname(require.resolve('pdfjs-dist/package.json'));
const INPUT = resolve(HERE, 'fixtures/sample.pdf');
const P12 = resolve(HERE, '../../../..', 'packages/signer/tests/fixtures/rsa2048-valid.p12');

async function signInWizard(page: Page, input: string, output: string) {
  await page.goto('/#/firmar');
  await page.locator('input[type="file"]').first().setInputFiles(input);
  await expect(page.locator('.sig-box')).toBeVisible();
  if (input !== INPUT) {
    await page.locator('.sig-box').dragTo(page.locator('.box-overlay'), {
      sourcePosition: { x: 10, y: 10 },
      targetPosition: { x: 40, y: 60 },
    });
  }
  await page
    .getByRole('button', { name: /^continuar$|^continue$/i })
    .last()
    .click();
  await page.locator('input[type="file"]').first().setInputFiles(P12);
  const pin = page.locator('input[type="password"]').first();
  await pin.fill('test1234');
  await pin.press('Enter');
  await expect(
    page.getByRole('heading', { name: /listo para firmar|ready to sign/i }),
  ).toBeVisible();
  const pending = page.waitForEvent('download');
  await page.getByRole('button', { name: /^firmar pdf$|^sign pdf$/i }).click();
  const download = await pending;
  expect(await download.failure()).toBeNull();
  await download.saveAs(output);
  await expect(
    page.getByRole('heading', { name: /pdf firmado correctamente|pdf signed successfully/i }),
  ).toBeVisible();
  const bytes = readFileSync(output);
  const crypto = verifyPadesIndependently(bytes);
  expect(crypto, crypto.failure).toMatchObject({
    byteRangeCoversDocument: true,
    digestMatches: true,
    signatureValid: true,
  });
  return bytes;
}

/** Test-only PDF.js viewer. The Link comes from the downloaded PDF, never a hand-made <a>. */
async function openPdfViewer(page: Page, bytes: Buffer) {
  const assets: Record<string, [string, string]> = {
    'pdf.mjs': ['build/pdf.mjs', 'text/javascript'],
    'pdf.worker.mjs': ['build/pdf.worker.mjs', 'text/javascript'],
    'viewer.mjs': ['web/pdf_viewer.mjs', 'text/javascript'],
    'viewer.css': ['web/pdf_viewer.css', 'text/css'],
  };
  await page.route('**/__qr_e2e/**', async (route) => {
    const name = new URL(route.request().url()).pathname.split('/').pop()!;
    if (name === 'document.pdf')
      return route.fulfill({ contentType: 'application/pdf', body: bytes });
    const asset = assets[name];
    if (asset)
      return route.fulfill({ contentType: asset[1], body: readFileSync(resolve(PDFJS, asset[0])) });
    if (name !== 'index.html') return route.fulfill({ status: 404 });
    return route.fulfill({
      contentType: 'text/html',
      body: `<!doctype html>
      <html><head><meta name="viewport" content="width=device-width, initial-scale=1"><link rel="stylesheet" href="viewer.css"></head>
      <body><div id="viewer" class="pdfViewer"></div><script type="module">
      import * as pdfjs from './pdf.mjs';
      import { PDFPageView, PDFLinkService, EventBus } from './viewer.mjs';
      pdfjs.GlobalWorkerOptions.workerSrc = './pdf.worker.mjs';
      const pdf = await pdfjs.getDocument('./document.pdf').promise;
      const page = await pdf.getPage(1);
      const eventBus = new EventBus();
      const linkService = new PDFLinkService({ eventBus, externalLinkTarget: 0 });
      linkService.setDocument(pdf);
      const view = new PDFPageView({ container: document.getElementById('viewer'), id: 1,
        defaultViewport: page.getViewport({ scale: 1 }), eventBus, linkService,
        annotationMode: pdfjs.AnnotationMode.ENABLE_FORMS });
      view.setPdfPage(page);
      await view.draw();
      </script></body></html>`,
    });
  });
  await page.goto('/__qr_e2e/index.html');
}

test('QR click golden path: signed download and second signature open the verifier', async ({
  page,
  context,
  baseURL,
}, testInfo) => {
  test.setTimeout(150_000);
  await context.route('**/api/stats**', (route) => route.fulfill({ status: 204 }));
  const firstPath = testInfo.outputPath('qr-first.pdf');
  const first = await signInWizard(page, INPUT, firstPath);
  await page.getByRole('button', { name: /firmar otro pdf|sign another pdf/i }).click();
  const secondPath = testInfo.outputPath('qr-second.pdf');
  const second = await signInWizard(page, firstPath, secondPath);
  expect(second.subarray(0, first.length).equals(first)).toBe(true);

  const pdf = await getDocument({ data: new Uint8Array(second), isEvalSupported: false }).promise;
  const annotations = await (await pdf.getPage(1)).getAnnotations();
  const links = annotations.filter((a) => a.subtype === 'Link');
  expect(links).toHaveLength(2);
  expect(annotations.filter((a) => a.subtype === 'Widget' && a.fieldType === 'Sig')).toHaveLength(
    2,
  );
  const target = new URL(links[1].url);
  expect(target.origin).toBe('https://app.firmar.ec');
  expect(target.hash).toMatch(/^#\/verificar\?h=[a-f0-9]{12}$/);
  await pdf.destroy();

  // A local run follows the real production href through a test-only redirect.
  // Live runs follow it directly. No production route/config is changed.
  if (new URL(baseURL!).origin !== target.origin) {
    await page.route(`${target.origin}/`, (route) =>
      route.fulfill({ status: 302, headers: { location: new URL('/', baseURL!).href } }),
    );
  }
  await openPdfViewer(page, second);
  const anchors = page.locator('.annotationLayer .linkAnnotation a');
  await expect(anchors).toHaveCount(2);
  const targetLink = page.locator(`.annotationLayer .linkAnnotation a[href="${target.href}"]`);
  await expect(targetLink).toBeVisible();
  await targetLink.click();
  await expect(page).toHaveURL(
    new RegExp(`${target.hash.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`),
  );
  await expect(
    page.getByRole('heading', {
      name: /Llegaste desde un QR de firmar.ec|You arrived from a firmar.ec QR/i,
    }),
  ).toBeVisible();
  await page.locator('input[type="file"]').first().setInputFiles(secondPath);
  await expect(page.getByText(/2 firmas detectadas|2 signatures detected/i)).toBeVisible();
  await expect(page.getByText('Test Signer RSA-2048', { exact: false }).first()).toBeVisible();
  await expect(
    page
      .getByText(/firma es criptográficamente correcta|signature is cryptographically correct/i)
      .first(),
  ).toBeVisible();
});
