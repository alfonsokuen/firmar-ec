// Astro 5: uses glob() loaders instead of deprecated type:'content'.
// This avoids the deprecation warning that breaks astro check in strict mode.
import { defineCollection, z } from 'astro:content';
import { glob } from 'astro/loaders';

const faq = defineCollection({
  loader: glob({ pattern: '**/*.md', base: './src/content/faq' }),
  schema: z.object({
    question: z.string(),
    lang: z.enum(['es', 'en']),
    order: z.number().default(100),
    tags: z.array(z.string()).default([]),
  }),
});

const glosario = defineCollection({
  loader: glob({ pattern: '**/*.md', base: './src/content/glosario' }),
  schema: z.object({
    term: z.string(),
    lang: z.enum(['es', 'en']),
    acronym: z.string().optional(),
    seeAlso: z.array(z.string()).default([]),
  }),
});

const pages = defineCollection({
  loader: glob({ pattern: '**/*.md', base: './src/content/pages' }),
  schema: z.object({
    title: z.string(),
    description: z.string(),
    lang: z.enum(['es', 'en']),
    datePublished: z.string(),
    dateModified: z.string().optional(),
    h1: z.string().optional(),
    breadcrumbs: z.array(z.object({ name: z.string(), url: z.string() })).default([]),
    related: z.array(z.object({ title: z.string(), href: z.string() })).default([]),
  }),
});

/** Colección `respuestas` — una pregunta real de un motor generativo por
 *  página, respondida ARRIBA y en texto VISIBLE.
 *
 *  POR QUÉ NO ES UN SEAM JSON: un motor no cita texto que no se ve. Publicar
 *  FAQPage sin pintar nada deja el hueco abierto (lección de idkmanager-web:
 *  el mismo hueco reapareció tres veces con el schema ya en producción). Por
 *  eso una respuesta vive aquí, como contenido, y la guarda de build
 *  `scripts/check-answer-pages.mjs` verifica sobre el HTML CONSTRUIDO que
 *  la plantilla la pinta de verdad.
 *
 *  ESTE ESQUEMA ES UN CONTRATO CON EL MOTOR, NO UNA PREFERENCIA LOCAL. Las
 *  entradas las escribe un bot (idkpublicitaria, artefacto `answer_page`), y
 *  las claves y su orden son los que fija `domain/answerPage.ts`
 *  (`FRONTMATTER_KEYS`). Se replica el de idkmanager-web A PROPÓSITO: dos
 *  formas canónicas del mismo fichero, sin nada que las cruce, es un fallo ya
 *  vivido. Si el motor cambia el contrato, este esquema cambia con él.
 *
 *  `.strict()` ES LOAD-BEARING: zod descarta en silencio las claves que no
 *  declara, así que un desajuste bot↔sitio se manifestaría como una página
 *  incompleta EN VERDE. Con `.strict()` rompe el build, que es la señal
 *  correcta.
 *
 *  OJO CON `firmar.ec`: es propiedad YMYL y publica sin revisión humana. Lo que
 *  impide que salga una afirmación sin respaldo NO es este esquema, sino dos
 *  filtros del motor sobre los claims aprobados del brand brief: el anclaje por
 *  cobertura (`domain/answerPageAnchoring.ts`, exige que cada oración factual
 *  comparta ≥60% de vocabulario con algún claim) y el rechazo de términos
 *  regulados que ningún claim sostenga (`hasUnclaimedYmylSignal`).
 *
 *  Y ese segundo filtro es de VOCABULARIO, no de veracidad: una frase
 *  jurídicamente peligrosa que no use ninguno de esos términos le resulta
 *  invisible. Conviene saberlo antes de confiar en él más de la cuenta. */
const respuestas = defineCollection({
  loader: glob({ pattern: '**/*.md', base: './src/content/respuestas' }),
  schema: z
    .object({
      title: z.string().min(1),
      description: z.string().min(1),
      question: z.string().min(10).max(200),
      answer: z.string().min(1),
      pubDate: z.coerce.date(),
      updatedDate: z.coerce.date().optional(),
      /** 3-5 pares: el mínimo evita un FAQPage anémico; el máximo evita que la
       *  página degenere en un volcado de preguntas sin cuerpo. */
      faq: z
        .array(z.object({ q: z.string().min(1), a: z.string().min(1) }))
        .min(3)
        .max(5),
      /** Rutas internas con barra final (`trailingSlash: 'always'`). Una ruta
       *  que ya no existe se DESCARTA al renderizar, no rompe el build: si
       *  rompiera, borrar una respuesta —que es exactamente la reversión del
       *  bot— tumbaría el sitio entero y dejaría la marcha atrás bloqueada. */
      relatedSlugs: z
        .array(z.string().regex(/^\/[a-z0-9/-]+\/$/))
        .default([]),
      /** Ids de claim del brand brief que anclan las frases factuales, para
       *  poder auditar después la procedencia de cada afirmación. */
      evidenceClaims: z.array(z.string()).default([]),
      recommendationId: z.number().int().positive().optional(),
      generator: z.string().optional(),
      promptVersion: z.string().optional(),
    })
    .strict(),
});

export const collections = { faq, glosario, pages, respuestas };
