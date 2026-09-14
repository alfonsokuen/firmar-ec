import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
/**
 * E2E — /firmar wizard (Sprint C Batch 9).
 *
 * Batch 9: PdfPreview `effect_update_depth_exceeded` resolved by wrapping the
 * `onPageRender` callback (and `onLoaded` / `currentPage` clamps) in
 * `untrack()` so parent state writes don't feed back as reactive deps of the
 * surrounding `$effect`. Tests 1, 2, 4 re-enabled below.
 *
 * Test 3 (multi-firma) still fixme — pending pre-signed fixture script.
 * Test 32 (cross-verify) still fixme — needs real TSL, not placeholder.
 *
 * @see apps/pwa/playwright.config.ts
 * @see apps/pwa/src/ui/firma/PdfPreview.svelte (untrack fix)
 */
import { type Page, expect, test } from '@playwright/test';
import { verifyPadesIndependently } from './helpers/lote-verify';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE_PDF = resolve(HERE, 'fixtures/sample.pdf');
const REPO_ROOT = resolve(HERE, '..', '..', '..', '..');
const FIXTURE_P12_VALID = resolve(REPO_ROOT, 'packages/signer/tests/fixtures/rsa2048-valid.p12');
const FIXTURE_P12_EXPIRED = resolve(REPO_ROOT, 'packages/signer/tests/fixtures/cert-expired.p12');
const VALID_PIN = 'test1234';

/** Capture pageerrors so we can assert NO Svelte effect-loop fires. */
function attachErrorCapture(page: Page): { errors: string[] } {
  const errors: string[] = [];
  page.on('pageerror', (err) => {
    errors.push(err.message);
    // eslint-disable-next-line no-console
    console.log('[browser:pageerror]', err.message);
  });
  return { errors };
}

// ── Step helpers ─────────────────────────────────────────────────────────

/** Step 1 → drop a PDF. Advances to step 2 (place box). */
async function step1DropPdf(page: Page, pdfPath: string): Promise<void> {
  const pdfInput = page.locator('input[type="file"]').first();
  await pdfInput.waitFor({ state: 'attached' });
  await pdfInput.setInputFiles(pdfPath);
  await expect(
    page.getByRole('heading', { name: /coloca tu cuadro|place your signature/i }),
  ).toBeVisible({ timeout: 15_000 });
}

/** Step 2 → BoxPlacer auto-places a default centered box on first pageRender;
 * the user can drag it; then click the wizard footer "Continuar" to advance.
 * v0.4.2: the duplicate confirm-bar inside BoxPlacer was removed. The wizard
 * footer Next button is the single advance CTA. */
async function step2PlaceBox(page: Page): Promise<void> {
  // Wait for the BoxPlacer overlay to mount (depends on pageInfo callback firing).
  const overlay = page.locator('.box-overlay');
  await overlay.waitFor({ state: 'visible', timeout: 15_000 });
  // Wait for the auto-placed signature box to appear (default centered position).
  await page.locator('.sig-box').waitFor({ state: 'visible', timeout: 10_000 });
  // Click wizard footer Next ("Continuar"/"Continue"). canNext is true now.
  const nextBtn = page.getByRole('button', { name: /^continuar$|^continue$/i }).last();
  await nextBtn.click();
  await expect(
    page.getByRole('heading', { name: /tu certificado|your \.p12 certificate/i }),
  ).toBeVisible({ timeout: 10_000 });
}

/** Step 3 → drop the .p12. Advances to step 4 (PIN). */
async function step3DropP12(page: Page, p12Path: string): Promise<void> {
  // The DropP12 file input is the only file input now visible (PDF input is unmounted).
  const p12Input = page.locator('input[type="file"]').first();
  await p12Input.waitFor({ state: 'attached' });
  await p12Input.setInputFiles(p12Path);
  await expect(
    page.getByRole('heading', {
      name: /escribe tu contraseña|enter your password|tu contraseña|password/i,
    }),
  ).toBeVisible({ timeout: 10_000 });
}

/** Step 4 → enter PIN + submit. */
async function step4Pin(page: Page, pin: string): Promise<void> {
  const pinInput = page
    .locator('input[type="password"], input[type="text"][autocomplete="off"]')
    .first();
  await pinInput.waitFor({ state: 'visible' });
  await pinInput.fill(pin);
  // Submit via Enter — PinInput has onkeydown handler; avoids ambiguity with
  // the show/hide eye toggle button which shares partial label text.
  await pinInput.press('Enter');
}

test.describe('firmar.ec — /firmar wizard', () => {
  test('Test S1 — /#/firmar route loads with wizard heading + step 1 drop zone', async ({
    page,
  }) => {
    const cap = attachErrorCapture(page);
    await page.goto('/#/firmar');
    await expect(page.getByRole('heading', { name: /firmar pdf|sign pdf/i })).toBeVisible();
    const pdfInput = page.locator('input[type="file"]').first();
    await expect(pdfInput).toBeAttached();
    await expect(page.getByRole('heading', { name: /sube tu pdf|upload your pdf/i })).toBeVisible();
    expect(cap.errors).toEqual([]);
  });

  test('Test S2 — dropping a valid PDF advances to step 2 heading (no effect-loop)', async ({
    page,
  }) => {
    const cap = attachErrorCapture(page);
    await page.goto('/#/firmar');
    await step1DropPdf(page, FIXTURE_PDF);
    // BoxPlacer overlay must mount → proves pageInfo callback fired without
    // triggering effect_update_depth_exceeded.
    await expect(page.locator('.box-overlay')).toBeVisible({ timeout: 15_000 });
    expect(cap.errors.filter((e) => /effect_update_depth_exceeded/.test(e))).toEqual([]);
  });

  test('Test 1 — golden path (drop PDF → place box → drop .p12 → PIN → sign → step 6)', async ({
    page,
  }) => {
    const cap = attachErrorCapture(page);
    await page.goto('/#/firmar');
    await step1DropPdf(page, FIXTURE_PDF);
    await step2PlaceBox(page);
    await step3DropP12(page, FIXTURE_P12_VALID);
    await step4Pin(page, VALID_PIN);
    // Step 5 (summary) — the "Detalles opcionales" step was removed in
    // v0.7.15; PIN submission goes straight to the summary. Hit Firmar PDF.
    await expect(
      page.getByRole('heading', { name: /listo para firmar|ready to sign/i }),
    ).toBeVisible({ timeout: 10_000 });
    const downloadPromise = page.waitForEvent('download');
    await page.getByRole('button', { name: /^firmar pdf$|^sign pdf$/i }).click();
    // Step 6 — success heading.
    await expect(
      page.getByRole('heading', { name: /pdf firmado correctamente|pdf signed successfully/i }),
    ).toBeVisible({ timeout: 30_000 });
    const download = await downloadPromise;
    expect(await download.failure()).toBeNull();
    const report = verifyPadesIndependently(readFileSync((await download.path())!));
    expect(report, report.failure).toMatchObject({
      byteRangeCoversDocument: true,
      digestMatches: true,
      signatureValid: true,
    });
    expect(cap.errors.filter((e) => /effect_update_depth_exceeded/.test(e))).toEqual([]);
  });

  test('Test 2 — PIN incorrecto: error visible + permanece en paso 4', async ({ page }) => {
    const cap = attachErrorCapture(page);
    await page.goto('/#/firmar');
    await step1DropPdf(page, FIXTURE_PDF);
    await step2PlaceBox(page);
    await step3DropP12(page, FIXTURE_P12_VALID);
    await step4Pin(page, 'wrong-pin-xyz');
    // Inline PIN error (aria-live="polite", id="pin-error") must appear.
    await expect(page.locator('#pin-error')).toBeVisible({ timeout: 10_000 });
    // Still on step 4 — heading "Certificate password" remains visible.
    await expect(
      page.getByRole('heading', { name: /contraseña.*certificado|certificate password/i }),
    ).toBeVisible();
    expect(cap.errors.filter((e) => /effect_update_depth_exceeded/.test(e))).toEqual([]);
  });

  test.fixme(
    'Test 3 — multi-firma: ExistingSignaturesPanel + 2nd sig (pending pre-signed fixture script)',
    async ({ page }) => {
      // TODO Batch 10: add packages/signer/scripts/gen-pre-signed-pdf.ts that
      // writes apps/pwa/tests/e2e/fixtures/sample-presigned.pdf via signPdfPades
      // with rsa2048-valid.p12, then activate this test.
      void page;
    },
  );

  test('Test 4 — certificado expirado mapea a cert_expired', async ({ page }) => {
    const cap = attachErrorCapture(page);
    await page.goto('/#/firmar');
    await step1DropPdf(page, FIXTURE_PDF);
    await step2PlaceBox(page);
    await step3DropP12(page, FIXTURE_P12_EXPIRED);
    await step4Pin(page, VALID_PIN);
    // cert_expired UI error banner should appear (role=alert at top of body).
    const alert = page.getByRole('alert').first();
    await expect(alert).toBeVisible({ timeout: 10_000 });
    await expect(alert).toContainText(/expirad|expired/i);
    expect(cap.errors.filter((e) => /effect_update_depth_exceeded/.test(e))).toEqual([]);
  });

  test.fixme(
    'Test 32 — cross-verify: PDF firmado en /verificar = válido + DEMO banner (needs real TSL)',
    async ({ page }) => {
      // TODO: requires real TSL feed; current placeholders only emit a warning,
      // not a "valid" verdict. Re-enable once TSL plumbing lands.
      void page;
    },
  );
});
