import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
/**
 * E2E — "Validar certificado" muestra a la EMPRESA en un certificado de
 * representante legal (navegador real, Worker real, parseo real del .p12).
 *
 * Por qué hace falta además de los unitarios: `ec-identity.test.ts` prueba que
 * el parser LEE cargo y razón social del arco de la ACE, y `certCheck` que
 * viajan en el `CertCheckResult`. Ninguno prueba que la página los PINTE —que
 * es justo lo que faltaba: los datos ya venían en el certificado y nadie los
 * mostraba. Un campo desconectado en la plantilla pasa los unitarios enteros.
 *
 * Se ejercita en los DOS idiomas. La app elige por `navigator.language`, y una
 * clave añadida solo al catálogo español deja la ficha en inglés mostrando el
 * identificador crudo; afirmar las etiquetas traducidas lo caza.
 *
 * Fixture: `global-setup.ts` genera el .p12 al vuelo con la identidad de
 * `helpers/rep-legal-fixture.ts` — inventada. Un certificado de representante
 * legal REAL lleva la cédula de una persona viva y el RUC de una empresa real,
 * y ninguno puede entrar en este repositorio.
 *
 * El certificado es autofirmado, así que la página lo reporta como no
 * acreditado. Da igual aquí: lo que se afirma es que los tres campos se
 * renderizan, y también el caso negativo —un certificado de persona natural NO
 * debe pintar filas de empresa vacías.
 *
 * @see apps/pwa/tests/e2e/global-setup.ts (generación del fixture)
 * @see apps/pwa/src/routes/ValidarCertificado.svelte (la ficha)
 * @see packages/crypto-core/src/ec-identity.ts (sufijos .5 / .10 / .11)
 */
import { type Page, expect, test } from '@playwright/test';
import { E2E_REP_LEGAL_ATTRS, E2E_REP_LEGAL_CN } from './helpers/rep-legal-fixture';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE_REP_LEGAL_P12 = resolve(HERE, 'fixtures/generated/test-representante-legal.p12');
/** Persona natural: mismo generador, sin `.5` ni `.10` — el caso negativo. */
const FIXTURE_NATURAL_P12 = resolve(HERE, 'fixtures/generated/test-signer.p12');
const VALID_PIN = 'test1234';

/** Etiquetas de la ficha por idioma, tal y como las ve quien la usa. */
const LABELS = {
  es: {
    locale: 'es-EC',
    submit: /^Validar certificado$/,
    titular: 'Titular',
    cedula: 'Cédula',
    ruc: 'RUC de la empresa',
    rucPropio: 'RUC',
    razonSocial: 'Razón social',
    cargo: 'Cargo',
  },
  en: {
    locale: 'en-US',
    submit: /^Validate certificate$/,
    titular: 'Holder',
    cedula: 'National ID',
    ruc: 'Company tax ID (RUC)',
    rucPropio: 'Tax ID (RUC)',
    razonSocial: 'Company',
    cargo: 'Role',
  },
} as const;

/** Sube el .p12, teclea el PIN y espera a que la ficha esté pintada. */
async function validarCert(
  page: Page,
  p12Path: string,
  labels: (typeof LABELS)[keyof typeof LABELS],
): Promise<void> {
  await page.goto('/#/validar-certificado');

  await page.locator('input[type="file"]').first().setInputFiles(p12Path);
  const pin = page.locator('input[type="password"]').first();
  await pin.waitFor({ state: 'visible' });
  await pin.fill(VALID_PIN);
  await page.getByRole('button', { name: labels.submit }).click();

  // La ficha es un <dl>; esperar al primer término evita afirmar sobre la
  // pantalla anterior si el worker aún no ha respondido.
  await expect(fila(page, labels.titular)).toBeVisible({ timeout: 30_000 });
}

/**
 * El `<dt>` cuya etiqueta es exactamente `label`.
 *
 * `:text-is()` compara el texto completo, sin regex: escribir `\(` a mano en un
 * literal ya convirtio una vez el parentesis en un grupo de captura, y la
 * comparacion dejaba de casar sin que el test dijera nada util. `JSON.stringify`
 * pone las comillas y escapa lo que haga falta.
 */
function fila(page: Page, label: string) {
  return page.locator(`dt:text-is(${JSON.stringify(label)})`);
}

/** El valor (`<dd>`) de esa fila. */
function valorDe(page: Page, label: string) {
  return fila(page, label).locator('+ dd');
}

for (const [lang, labels] of Object.entries(LABELS)) {
  test.describe(`Validar certificado — representante legal (${lang})`, () => {
    test.use({ locale: labels.locale });

    test('pinta RUC, razón social y cargo de la empresa representada', async ({ page }) => {
      await validarCert(page, FIXTURE_REP_LEGAL_P12, labels);

      await expect(valorDe(page, labels.titular)).toHaveText(E2E_REP_LEGAL_CN);
      await expect(valorDe(page, labels.cedula)).toHaveText(E2E_REP_LEGAL_ATTRS['1']!);

      // Los tres campos que faltaban. El RUC es el de la EMPRESA: no empieza
      // por la cédula del titular, que es lo que lo hace ilegible a solas.
      await expect(valorDe(page, labels.ruc)).toHaveText(E2E_REP_LEGAL_ATTRS['11']!);
      await expect(valorDe(page, labels.razonSocial)).toHaveText(E2E_REP_LEGAL_ATTRS['10']!);
      await expect(valorDe(page, labels.cargo)).toHaveText(E2E_REP_LEGAL_ATTRS['5']!);

      // El RUC es de la EMPRESA: no empieza por la cedula del titular, y la
      // ficha debe DECIRLO. Sin esa etiqueta, el numero de una empresa se lee
      // como un dato de la persona — el error que esta pantalla evita.
      expect(E2E_REP_LEGAL_ATTRS['11']!.startsWith(E2E_REP_LEGAL_ATTRS['1']!)).toBe(false);
      await expect(fila(page, labels.rucPropio)).toHaveCount(0);
    });

    test('un certificado sin empresa no deja filas vacías', async ({ page }) => {
      // Mismo generador, sin los atributos de empresa: las tres filas no
      // existen. Sin esto, un `{#if}` mal puesto pintaría "Cargo —" a todos.
      await validarCert(page, FIXTURE_NATURAL_P12, labels);

      await expect(fila(page, labels.razonSocial)).toHaveCount(0);
      await expect(fila(page, labels.cargo)).toHaveCount(0);
      await expect(fila(page, labels.ruc)).toHaveCount(0);
    });
  });
}
