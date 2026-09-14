/**
 * check-nav-links — guarda HERMÉTICA (sin red) sobre el `dist` construido.
 *
 * Fija dos decisiones que ya se rompieron una vez (bug reportado 2026-09-02):
 *  1. "Validar certificado" en el menú es una ACCIÓN: la cabecera enlaza la
 *     herramienta en la app y NO el artículo SEO.
 *  2. El artículo no puede quedarse sin enlace de todo el sitio: el PIE lo
 *     enlaza en las dos lenguas (perdió sus 76 anclas al mover el menú).
 *
 * Se busca por `href`, nunca por el texto del enlace. El rótulo vive en
 * `src/i18n/ui.ts` y cambia con el tiempo; copiarlo aquí crearía un segundo
 * origen de verdad que nadie sincroniza. Además, emparejar por texto exige que
 * el ancla no tenga hijos: medido sobre el `dist`, una regex así sólo ve 50 de
 * las 77 anclas de la home, y basta meter un icono dentro del enlace —el patrón
 * habitual de este menú— para que la guarda enrojezca SIN que exista bug. Con
 * `merge = deploy`, ese falso positivo bloquearía hasta un hotfix.
 *
 * Corre dentro de `pnpm build`, así que la ejercita el CI (pr-check y deploy).
 * El canary Playwright equivalente habla con producción y no puede ser gate.
 */
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DIST = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../dist');
const TOOL_URL = 'https://app.firmar.ec/#/validar-certificado';
const ARTICLE = { es: '/validar-certificado/', en: '/en/validate-certificate/' };

const PAGES = [
  { file: 'index.html', lang: 'es' },
  { file: 'en/index.html', lang: 'en' },
];

/** Recorta una región del HTML por su etiqueta, o null si no está. */
function region(html, tag) {
  const start = html.indexOf(`<${tag}`);
  if (start === -1) return null;
  const end = html.indexOf(`</${tag}>`, start);
  return end === -1 ? null : html.slice(start, end);
}

const errors = [];

for (const { file, lang } of PAGES) {
  const html = await readFile(path.join(DIST, file), 'utf8');
  const header = region(html, 'header');
  const footer = region(html, 'footer');
  const signCta = html.match(/<a\b[^>]*\bdata-cta="firmar"[^>]*>/)?.[0];
  if (!signCta?.includes('href="https://app.firmar.ec/#/firmar"')) {
    errors.push(`${file}: el CTA de firma debe abrir directamente la ruta de firma en la app`);
  }

  if (header === null) {
    errors.push(`${file}: no encuentro <header> — ¿cambió la plantilla?`);
  } else {
    if (!header.includes(`href="${TOOL_URL}"`)) {
      errors.push(`${file}: la cabecera no enlaza la herramienta (${TOOL_URL})`);
    }
    if (header.includes(`href="${ARTICLE[lang]}"`)) {
      errors.push(
        `${file}: la cabecera volvió a enlazar el artículo (${ARTICLE[lang]}); debe ir a la herramienta`,
      );
    }
  }

  if (footer === null) {
    errors.push(`${file}: no encuentro <footer> — ¿cambió la plantilla?`);
  } else if (!footer.includes(`href="${ARTICLE[lang]}"`)) {
    errors.push(
      `${file}: el pie no enlaza el artículo (${ARTICLE[lang]}); sin él se queda sin enlace de todo el sitio`,
    );
  }
}

if (errors.length > 0) {
  console.error('check-nav-links FALLÓ:');
  for (const e of errors) console.error(`  • ${e}`);
  process.exit(1);
}
console.log(`check-nav-links OK: cabecera → herramienta y pie → artículo en ${PAGES.length} lenguas`);
