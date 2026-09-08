// Tests de los DETECTORES post-build. Existen porque un detector sin test se
// degrada en silencio: `check-llms` y `check-answer-pages` corren sobre `dist`
// y, si se debilitan, el build sigue VERDE por construcción — una exención más
// ancha nunca produce un `missing`, y un guarda que deja de mirar no falla,
// simplemente deja de encontrar. `astro build` devuelve 0 en los tres modos de
// rotura de una answer page: el único detector del detector es este fichero.
//
// El corpus va en AMBAS direcciones a propósito (regla del proyecto para
// cualquier cambio de detector): cada caso que debe cazarse tiene su pareja que
// NO debe disparar. Un test que solo afirma la dirección positiva se queda
// verde cuando alguien convierte el guarda en un no-op.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isExempt } from '../scripts/check-llms.mjs';
import { checkAnswerHtml, parseAnswerFrontmatter, decodeText } from '../scripts/check-answer-pages.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

// ── check-llms: exenciones por prefijo ──────────────────────────────────────
describe('check-llms — isExempt', () => {
  it('NO exime una página normal: sigue siendo obligatoria en llms.txt', () => {
    expect(isExempt('https://firmar.ec/glosario/')).toBe(false);
    expect(isExempt('https://firmar.ec/precios/')).toBe(false);
  });

  it('NO exime el HUB de la sección, aunque sea el prefijo exento', () => {
    // El `url !== p` de la implementación. Sin él, el hub dejaría de exigirse en
    // llms.txt y la sección entera quedaría invisible para su destinatario.
    expect(isExempt('https://firmar.ec/respuestas/')).toBe(false);
  });

  it('SÍ exime las páginas individuales de la sección', () => {
    // Las escribe el bot, una por PR; el llms.txt lo mantiene otro ciclo.
    expect(isExempt('https://firmar.ec/respuestas/lo-que-sea/')).toBe(true);
    expect(isExempt('https://firmar.ec/respuestas/otra-cosa/')).toBe(true);
  });

  it('exime la home, que es el fichero mismo', () => {
    expect(isExempt('https://firmar.ec/')).toBe(true);
  });
});

// ── check-answer-pages: parser del frontmatter canónico ─────────────────────
const FM_CANONICO = `---
title: "T"
description: "D"
question: "¿Pregunta larga de verdad?"
answer: "La respuesta."
pubDate: "2026-09-07"
faq:
  - q: "P1"
    a: "R1"
  - q: "P2"
    a: "R2"
  - q: "P3"
    a: "R3"
relatedSlugs:
  - "/algo/"
---

## La respuesta corta

La respuesta.
`;

describe('check-answer-pages — parseAnswerFrontmatter', () => {
  it('acepta la forma canónica que emite el motor', () => {
    const fm = parseAnswerFrontmatter(FM_CANONICO);
    expect(fm).not.toBeNull();
    expect(fm.question).toBe('¿Pregunta larga de verdad?');
    expect(fm.answer).toBe('La respuesta.');
    expect(fm.faq).toHaveLength(3);
  });

  it('RECHAZA un escalar sin comillas JSON (forma no canónica)', () => {
    expect(parseAnswerFrontmatter(FM_CANONICO.replace('title: "T"', 'title: T'))).toBeNull();
  });

  it('RECHAZA la faq en JSON de una línea — el fallo del primer forjado real', () => {
    const enLinea = FM_CANONICO.replace(
      /faq:\n(  - q.*\n    a.*\n)+/,
      'faq: [{"q":"P1","a":"R1"}]\n',
    );
    expect(parseAnswerFrontmatter(enLinea)).toBeNull();
  });

  it('RECHAZA una faq con la respuesta vacía', () => {
    expect(parseAnswerFrontmatter(FM_CANONICO.replace('    a: "R1"', '    a: ""'))).toBeNull();
  });

  it('RECHAZA un fichero sin frontmatter', () => {
    expect(parseAnswerFrontmatter('# solo cuerpo\n')).toBeNull();
  });
});

// ── check-answer-pages: verificación del HTML construido ────────────────────
const FAQ = [
  { q: 'P1', a: 'R1' },
  { q: 'P2', a: 'R2' },
  { q: 'P3', a: 'R3' },
];
const ENTRY = {
  slug: 'una-respuesta',
  question: '¿Pregunta larga de verdad?',
  answer: 'La respuesta directa y visible.',
  faq: FAQ,
  hubHtml: '<a href="/respuestas/una-respuesta/">P</a>',
};
const faqLd = (n: number) =>
  `<script type="application/ld+json">${JSON.stringify({
    '@context': 'https://schema.org',
    '@type': 'FAQPage',
    mainEntity: FAQ.slice(0, n).map((f) => ({
      '@type': 'Question',
      name: f.q,
      acceptedAnswer: { '@type': 'Answer', text: f.a },
    })),
  })}</script>`;

/** Página sana. Reproduce la estructura REAL: el cuerpo que emite el motor
 *  repite la respuesta bajo `## La respuesta corta`, así que la respuesta
 *  aparece DOS veces. Esa repetición es justo lo que obliga al guarda a medir
 *  solo la zona anterior al primer h2 — un fixture sin ella deja pasar un
 *  guarda que mire la página entera (verificado: con la respuesta ausente del
 *  todo, ambas versiones del guarda dan el mismo veredicto y el test no
 *  distingue nada). */
const sana = () =>
  `<html><body><h1>¿Pregunta larga de verdad?</h1>` +
  `<p>La respuesta directa y visible.</p>` +
  `<h2>La respuesta corta</h2><p>La respuesta directa y visible.</p>` +
  `<h2>Otra seccion</h2><p>cuerpo</p>${faqLd(3)}</body></html>`;

describe('check-answer-pages — checkAnswerHtml', () => {
  it('VERDE: una página que pinta lo que declara', () => {
    expect(checkAnswerHtml(sana(), ENTRY)).toEqual({ ok: true });
  });

  it('ROJO: la respuesta solo aparece DEBAJO del primer h2, no en la cabecera', () => {
    // El modo de fallo que el guarda existe para evitar, y el que de verdad
    // ocurre: la plantilla deja de pintar el párrafo de cabecera y la respuesta
    // queda solo en el cuerpo. Como el cuerpo la repite, un guarda que mirase
    // la página entera daría VERDE aquí — por eso mide la zona sobre el h2.
    const html = sana().replace('<p>La respuesta directa y visible.</p><h2>', '<h2>');
    expect(html).toContain('La respuesta directa y visible.'); // sigue en el cuerpo
    expect(checkAnswerHtml(html, ENTRY).ok).toBe(false);
  });

  it('ROJO: la respuesta no aparece en NINGUNA parte de la página', () => {
    const html = sana().replaceAll('<p>La respuesta directa y visible.</p>', '');
    expect(checkAnswerHtml(html, ENTRY).ok).toBe(false);
  });

  it('ROJO: el h1 no es la pregunta declarada', () => {
    const html = sana().replace('<h1>¿Pregunta larga de verdad?</h1>', '<h1>Otro titulo</h1>');
    expect(checkAnswerHtml(html, ENTRY).ok).toBe(false);
  });

  it('ROJO: más de un h1', () => {
    const html = sana().replace('</body>', '<h1>segundo</h1></body>');
    expect(checkAnswerHtml(html, ENTRY).ok).toBe(false);
  });

  it('ROJO: el hub no enlaza la página (nace huérfana)', () => {
    const r = checkAnswerHtml(sana(), { ...ENTRY, hubHtml: '<a href="/faq/">otra cosa</a>' });
    expect(r.ok).toBe(false);
  });

  it('ROJO: la URL suelta en el hub NO basta, hace falta un href de verdad', () => {
    const hubHtml = '<script>{"url":"https://firmar.ec/respuestas/una-respuesta/"}</script>';
    expect(checkAnswerHtml(sana(), { ...ENTRY, hubHtml }).ok).toBe(false);
  });

  it('ROJO: dos bloques FAQPage en la misma página', () => {
    const html = sana().replace('</body>', `${faqLd(3)}</body>`);
    expect(checkAnswerHtml(html, ENTRY).ok).toBe(false);
  });

  it('ROJO: el FAQPage declara menos preguntas que el frontmatter', () => {
    const html = sana().replace(faqLd(3), faqLd(2));
    expect(checkAnswerHtml(html, ENTRY).ok).toBe(false);
  });

  it('la respuesta se reconoce aunque Astro escape entidades', () => {
    const entry = { ...ENTRY, answer: 'Comillas "dobles" y & ampersand.' };
    const html =
      `<html><body><h1>¿Pregunta larga de verdad?</h1>` +
      `<p>Comillas &quot;dobles&quot; y &amp; ampersand.</p>` +
      `<h2>x</h2>${faqLd(3)}</body></html>`;
    expect(checkAnswerHtml(html, entry)).toEqual({ ok: true });
  });

  it('decodeText resuelve &amp; en último lugar', () => {
    // Decodificarla antes convertiria `&amp;quot;` en `"` en vez de en `&quot;`.
    expect(decodeText('&amp;quot;')).toBe('&quot;');
  });
});

// ── La página semilla real del repo, extremo a extremo ──────────────────────
describe('check-answer-pages — la semilla del repo', () => {
  it('su frontmatter está en la forma canónica que exige el motor', () => {
    const md = readFileSync(
      join(HERE, '../src/content/respuestas/programa-gratuito-sirve-firmar-documentos-ecuador.md'),
      'utf8',
    );
    const fm = parseAnswerFrontmatter(md);
    expect(fm).not.toBeNull();
    expect(fm.faq.length).toBeGreaterThanOrEqual(3);
    expect(fm.faq.length).toBeLessThanOrEqual(5);
    // Cotas del motor (`ANSWER_WORDS`), para que la semilla escrita a mano no
    // sea un caso que el bot nunca produciria.
    const palabras = (fm.answer.match(/\S+/g) ?? []).length;
    expect(palabras).toBeGreaterThanOrEqual(30);
    expect(palabras).toBeLessThanOrEqual(90);
  });
});
